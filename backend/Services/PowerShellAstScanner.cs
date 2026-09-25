using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation.Language;
using System.Text;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Services
{
    public class PowerShellAstScanner : IPowerShellAstScanner
    {
        private static readonly HashSet<string> SuspiciousCmdlets = new(StringComparer.OrdinalIgnoreCase)
        {
            "Invoke-Expression", "IEX",
            "Invoke-Command", "ICM",
            "Start-Process", "saps",
            "Invoke-WmiMethod", "Invoke-CimMethod"
        };

        private static readonly HashSet<string> SuspiciousMethods = new(StringComparer.OrdinalIgnoreCase)
        {
            "DownloadString",
            "DownloadFile",
            "DownloadData",
            "OpenRead"
        };

        public bool IsPowerShellTarget(string fileName, string? textSnippet = null)
        {
            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            if (ext is ".ps1" or ".psm1" or ".psd1") return true;

            if (!string.IsNullOrEmpty(textSnippet))
            {
                if (textSnippet.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                    textSnippet.Contains("-ExecutionPolicy", StringComparison.OrdinalIgnoreCase) ||
                    textSnippet.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase) ||
                    textSnippet.Contains("New-Object", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public List<FileAnomalyRecord> AnalyzeScript(string filePath, string fileName, string scriptText)
        {
            var anomalies = new List<FileAnomalyRecord>();
            if (string.IsNullOrWhiteSpace(scriptText)) return anomalies;

            try
            {
                // Official PowerShell compiler parser - strips backticks & normalizes tokens automatically
                ScriptBlockAst ast = Parser.ParseInput(
                    scriptText,
                    out Token[] tokens,
                    out ParseError[] errors
                );

                AnalyzeAstInternal(ast, filePath, fileName, anomalies, recursionDepth: 0);
            }
            catch (Exception ex)
            {
                anomalies.Add(new FileAnomalyRecord
                {
                    FilePath = filePath,
                    FileName = fileName,
                    Category = "AST Parsing Warning",
                    Title = "PowerShell AST Analysis Exception",
                    Details = $"Parser encountered unexpected syntax structure: {ex.Message}",
                    Severity = AnomalySeverity.Low
                });
            }

            return anomalies;
        }

        private void AnalyzeAstInternal(
            ScriptBlockAst ast, 
            string filePath, 
            string fileName, 
            List<FileAnomalyRecord> anomalies, 
            int recursionDepth)
        {
            if (recursionDepth > 2) return; // Prevent infinite recursion on nested encoded cradles

            // 1. Detect Invoke-Expression (IEX) / Dynamic Execution Primitives
            var commandAsts = ast.FindAll(node => node is CommandAst, searchNestedScriptBlocks: true)
                                 .Cast<CommandAst>();

            foreach (var cmd in commandAsts)
            {
                string commandName = cmd.GetCommandName() ?? string.Empty;

                if (SuspiciousCmdlets.Contains(commandName))
                {
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = filePath,
                        FileName = fileName,
                        Category = "Malicious Script (AST Analysis)",
                        Title = $"Dangerous Dynamic Execution Cmdlet: {commandName}",
                        Details = $"Identified dynamic code execution cmdlet '{commandName}' at line {cmd.Extent.StartLineNumber}. Often used in fileless memory injection and dropper execution.",
                        Severity = AnomalySeverity.Critical
                    });
                }

                // Check command arguments for execution policy or hidden window bypass flags
                foreach (var element in cmd.CommandElements)
                {
                    string elText = element.Extent.Text;
                    if (elText.Contains("Bypass", StringComparison.OrdinalIgnoreCase) ||
                        elText.Contains("Unrestricted", StringComparison.OrdinalIgnoreCase))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = filePath,
                            FileName = fileName,
                            Category = "Malicious Script (AST Analysis)",
                            Title = "PowerShell ExecutionPolicy Bypass Flag",
                            Details = $"Detected ExecutionPolicy override switch at line {element.Extent.StartLineNumber}.",
                            Severity = AnomalySeverity.High
                        });
                    }

                    if (elText.Contains("Hidden", StringComparison.OrdinalIgnoreCase) && 
                        cmd.Extent.Text.Contains("-WindowStyle", StringComparison.OrdinalIgnoreCase))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = filePath,
                            FileName = fileName,
                            Category = "Malicious Script (AST Analysis)",
                            Title = "Stealth WindowStyle Hidden Switch",
                            Details = $"Detected stealth execution flag (-WindowStyle Hidden) concealing command execution window at line {element.Extent.StartLineNumber}.",
                            Severity = AnomalySeverity.High
                        });
                    }
                }
            }

            // 2. Detect Suspicious Method Invocations (even when split across quotes or backticks)
            var memberExpressions = ast.FindAll(node => node is InvokeMemberExpressionAst, searchNestedScriptBlocks: true)
                                       .Cast<InvokeMemberExpressionAst>();

            foreach (var member in memberExpressions)
            {
                // Member.Extent.Text normalizes quotes and backtick escapes
                string memberName = member.Member.Extent.Text.Trim('\'', '"', '`');

                if (SuspiciousMethods.Contains(memberName))
                {
                    anomalies.Add(new FileAnomalyRecord
                    {
                        FilePath = filePath,
                        FileName = fileName,
                        Category = "Malicious Script (AST Analysis)",
                        Title = $"Dynamic Download Cradle Invocation: .{memberName}()",
                        Details = $"Identified remote staging method call '.{memberName}()' at line {member.Extent.StartLineNumber}. Used to stage remote secondary payloads into memory.",
                        Severity = AnomalySeverity.Critical
                    });
                }
            }

            // 3. Detect Obfuscated String Concatenation Chains (+ operators inside commands)
            var binaryExpressions = ast.FindAll(node => node is BinaryExpressionAst, searchNestedScriptBlocks: true)
                                       .Cast<BinaryExpressionAst>()
                                       .Where(b => b.Operator == TokenKind.Plus);

            int excessiveConcatCount = 0;
            foreach (var bin in binaryExpressions)
            {
                if (bin.Left is StringConstantExpressionAst || bin.Right is StringConstantExpressionAst)
                {
                    excessiveConcatCount++;
                }
            }

            if (excessiveConcatCount >= 6)
            {
                anomalies.Add(new FileAnomalyRecord
                {
                    FilePath = filePath,
                    FileName = fileName,
                    Category = "Obfuscation Evasion (AST)",
                    Title = "Heavy String Concatenation Obfuscation Chain",
                    Details = $"Detected {excessiveConcatCount} '+' string concatenation operators. Typical signature of automated script obfuscators (e.g. Invoke-Obfuscation) attempting to evade static strings.",
                    Severity = AnomalySeverity.High
                });
            }

            // 4. Inspect Base64 Strings for Recursive AST Analysis
            var stringConstants = ast.FindAll(node => node is StringConstantExpressionAst, searchNestedScriptBlocks: true)
                                     .Cast<StringConstantExpressionAst>();

            foreach (var strConst in stringConstants)
            {
                string val = strConst.Value.Trim();
                if (val.Length >= 60 && IsValidBase64(val, out byte[]? decodedBytes) && decodedBytes != null)
                {
                    // PowerShell -EncodedCommand uses Unicode (UTF-16LE)
                    string decodedUnicode = Encoding.Unicode.GetString(decodedBytes);
                    string decodedUtf8 = Encoding.UTF8.GetString(decodedBytes);

                    string targetDecoded = decodedUnicode.Contains(' ') ? decodedUnicode : decodedUtf8;

                    if (targetDecoded.Contains("IEX", StringComparison.OrdinalIgnoreCase) ||
                        targetDecoded.Contains("Invoke-", StringComparison.OrdinalIgnoreCase) ||
                        targetDecoded.Contains("Download", StringComparison.OrdinalIgnoreCase) ||
                        targetDecoded.Contains("Net.WebClient", StringComparison.OrdinalIgnoreCase))
                    {
                        anomalies.Add(new FileAnomalyRecord
                        {
                            FilePath = filePath,
                            FileName = fileName,
                            Category = "Malicious Script (AST De-obfuscation)",
                            Title = "Decoded Base64 Execution Payload in AST",
                            Details = $"Successfully decoded embedded base64 payload at line {strConst.Extent.StartLineNumber}. Found hidden command primitives.",
                            Severity = AnomalySeverity.Critical
                        });

                        // Recursively analyze unpacked AST
                        try
                        {
                            var nestedAst = Parser.ParseInput(targetDecoded, out _, out _);
                            AnalyzeAstInternal(nestedAst, filePath, fileName, anomalies, recursionDepth + 1);
                        }
                        catch
                        {
                            // Ignored if decoded string is partial fragment
                        }
                    }
                }
            }
        }

        private static bool IsValidBase64(string s, out byte[]? decoded)
        {
            decoded = null;
            if (s.Length % 4 != 0) return false;

            try
            {
                decoded = Convert.FromBase64String(s);
                return decoded.Length > 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
