using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using UltimateWinUI.Models;

namespace UltimateWinUI.Services;

/// <summary>
/// Runs tweak options without ever showing a console:
///
///   apply/check options -> the option's script body (extracted verbatim from
///     the upstream script by the catalog generator) is staged in a fresh
///     per-run directory under an ACL-restricted work dir and run with
///     Windows PowerShell, hidden, output piped to the log view. The staged
///     file is held open read-shared while PowerShell runs, so its contents
///     cannot be swapped between staging and execution, and the staged
///     SHA256 is written to the log. The app itself runs elevated (see
///     app.manifest), so children inherit admin rights and the scripts
///     never relaunch into a visible console.
///
///   launch options -> opened through the shell (ms-settings pages, control
///     panel applets, websites, other apps).
/// </summary>
public sealed class Runner
{
    private readonly LogService _log;
    private readonly string _workDir;

    public Runner(LogService log)
    {
        _log = log;
        _workDir = Path.Combine(CatalogService.DataDir, "work");
        Directory.CreateDirectory(_workDir);
        HardenWorkDir();
    }

    public async Task<int> RunOptionAsync(Tweak tweak, TweakOption option, IReadOnlyList<string>? inputs = null)
    {
        if (option.Kind == "launch")
        {
            Launch(option);
            _log.Write($"{tweak.Name}: opened {option.Target}");
            return 0;
        }

        var runDir = NewRunDir();
        try
        {
            var fileName = $"{Sanitize(tweak.Id)}-{Sanitize(option.Label)}.ps1";
            var path = Path.Combine(runDir, fileName);
            var isArm64 = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture ==
                          System.Runtime.InteropServices.Architecture.Arm64;
            var body = isArm64 && option.Arm64Body != null ? option.Arm64Body : option.Body;
            if (isArm64 && option.Arm64Body != null)
                _log.Write("Using the ARM64 variant of this script (native ARM64 payload).");
            var script = "$ErrorActionPreference = 'Continue'\n" +
                         "$ProgressPreference = 'SilentlyContinue'\n" +
                         body;
            await File.WriteAllTextAsync(path, script);

            _log.Write($"--- {tweak.Name} -> {option.Label} ---");

            // Hold the staged file open with FileShare.Read until
            // PowerShell exits: its contents cannot be swapped between
            // the write above and execution, and the logged hash is the
            // hash of the bytes that ran.
            var bytes = await File.ReadAllBytesAsync(path);
            _log.Write($"Staged script SHA256: {Convert.ToHexString(SHA256.HashData(bytes))}");
            await using var hold = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var exit = await RunPowerShellHiddenAsync(path, inputs);
            _log.Write($"--- {tweak.Name} finished (exit {exit}) ---");
            return exit;
        }
        finally
        {
            DeleteRunDir(runDir);
        }
    }

    public void Launch(TweakOption option)
    {
        var target = option.Target;
        if (string.IsNullOrWhiteSpace(target))
        {
            // Fall back to running the body; it contains the Start-Process call.
            if (!string.IsNullOrWhiteSpace(option.Body))
                _ = RunInlineAsync(option.Body);
            return;
        }
        Process.Start(new ProcessStartInfo
        {
            FileName = target,
            UseShellExecute = true,
        });
    }

    public async Task CreateRestorePointAsync()
    {
        _log.Write("Creating restore point (UltimateWinUI)...");
        var runDir = NewRunDir();
        try
        {
            var path = Path.Combine(runDir, "restore-point.ps1");
            await File.WriteAllTextAsync(path,
                "Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue\n" +
                "Checkpoint-Computer -Description 'UltimateWinUI' -RestorePointType 'MODIFY_SETTINGS'\n");
            await using var hold = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var exit = await RunPowerShellHiddenAsync(path);
            _log.Write(exit == 0
                ? "Restore point created."
                : $"Restore point failed (exit {exit}). Continuing anyway; see log output above.");
        }
        finally
        {
            DeleteRunDir(runDir);
        }
    }

    private async Task RunInlineAsync(string body)
    {
        var runDir = NewRunDir();
        try
        {
            var path = Path.Combine(runDir, $"inline-{Guid.NewGuid():N}.ps1");
            await File.WriteAllTextAsync(path, body);
            await using var hold = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            await RunPowerShellHiddenAsync(path);
        }
        finally
        {
            DeleteRunDir(runDir);
        }
    }

    private string NewRunDir()
    {
        var dir = Path.Combine(_workDir, $"run-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void DeleteRunDir(string dir)
    {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }

    private void HardenWorkDir()
    {
        // The work dir holds scripts that run elevated. Restrict it to
        // SYSTEM and Administrators so another local user, or a
        // medium-integrity process of the same user, cannot pre-plant or
        // replace a staged script. Best effort: the app always runs as
        // administrator, but if the ACL change fails the per-run
        // randomized directory names still apply.
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var rights = FileSystemRights.FullControl;
            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                rights, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                rights, inheritance, PropagationFlags.None, AccessControlType.Allow));
            Directory.SetAccessControl(_workDir, security);
        }
        catch (Exception ex)
        {
            _log.Write("Could not restrict the work directory ACL: " + ex.Message);
        }
    }

    private async Task<int> RunPowerShellHiddenAsync(string scriptPath, IReadOnlyList<string>? inputs = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{scriptPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        var outputClosed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var errorClosed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var proc = new Process { StartInfo = psi };
        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data == null) outputClosed.TrySetResult(true);
            else _log.Write(e.Data);
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) errorClosed.TrySetResult(true);
            else _log.Write("ERR: " + e.Data);
        };

        try
        {
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
        }
        catch (Exception ex)
        {
            _log.Write("Failed to start PowerShell: " + ex.Message);
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch { }
            return -1;
        }

        try
        {
            // Feed known Read-Host prompts, then close stdin so any prompt that
            // was not represented in the app cannot hang in the hidden process.
            if (inputs != null)
                foreach (var line in inputs)
                    proc.StandardInput.WriteLine(line);
        }
        catch (Exception ex)
        {
            _log.Write("Failed to send input to PowerShell: " + ex.Message);
        }
        finally
        {
            try { proc.StandardInput.Close(); } catch { }
        }

        await proc.WaitForExitAsync();
        await Task.WhenAll(outputClosed.Task, errorClosed.Task);
        return proc.ExitCode;
    }

    private static string Sanitize(string value)
    {
        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
            if (!char.IsLetterOrDigit(chars[i]) && chars[i] != '-' && chars[i] != '_')
                chars[i] = '-';
        var s = new string(chars);
        return s.Length > 60 ? s[..60] : s;
    }
}
