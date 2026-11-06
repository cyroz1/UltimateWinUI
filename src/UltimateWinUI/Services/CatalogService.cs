using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using UltimateWinUI.Models;

namespace UltimateWinUI.Services;

public static class CatalogService
{
    public static CatalogDoc? Catalog { get; private set; }

    public static CatalogDoc Load()
    {
        if (Catalog != null) return Catalog;
        var path = Path.Combine(AppContext.BaseDirectory, "Assets", "tweaks.json");
        var json = File.ReadAllText(path);
        var doc = JsonSerializer.Deserialize<CatalogDoc>(json)
                  ?? throw new InvalidOperationException("tweaks.json could not be parsed.");
        foreach (var cat in doc.Categories)
            foreach (var tweak in cat.Tweaks)
                tweak.Parent = cat;
        Catalog = doc;
        return doc;
    }

    public static string DataDir
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "UltimateWinUI");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }
}

/// <summary>Small user settings, persisted as JSON in the data dir.</summary>
public sealed class AppSettings
{
    public bool CreateRestorePointBeforeApply { get; set; } = false;
    public bool ConfirmAdvanced { get; set; } = true;
    public string Theme { get; set; } = "System"; // System | Light | Dark
    public int? SettingsVersion { get; set; }

    private static string FilePath => Path.Combine(CatalogService.DataDir, "settings.json");

    // The consent-critical flags (ConfirmAdvanced,
    // CreateRestorePointBeforeApply) are stored separately, next to the
    // installed executable, where only administrators can write (the app
    // always runs elevated). settings.json lives in the per-user data
    // directory, where any process running as the user could flip
    // ConfirmAdvanced off and silently remove the Advanced review
    // dialog; values found there are therefore never honored for these
    // two flags.
    private static string ConsentPath => Path.Combine(AppContext.BaseDirectory, "consent.json");

    public sealed class ConsentFile
    {
        public bool ConfirmAdvanced { get; set; } = true;
        public bool CreateRestorePointBeforeApply { get; set; }
    }

    public static AppSettings Load()
    {
        AppSettings settings;
        try
        {
            settings = File.Exists(FilePath)
                ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings()
                : new AppSettings { SettingsVersion = 2 };
        }
        catch { settings = new AppSettings { SettingsVersion = 2 }; }

        // Fail closed: the two consent flags start from their safe
        // defaults and are then taken from consent.json only.
        settings.ConfirmAdvanced = true;
        settings.CreateRestorePointBeforeApply = false;
        try
        {
            if (File.Exists(ConsentPath))
            {
                var consent = JsonSerializer.Deserialize<ConsentFile>(File.ReadAllText(ConsentPath));
                if (consent != null)
                {
                    settings.ConfirmAdvanced = consent.ConfirmAdvanced;
                    settings.CreateRestorePointBeforeApply = consent.CreateRestorePointBeforeApply;
                }
            }
        }
        catch { /* keep the safe defaults */ }

        if (!settings.SettingsVersion.HasValue || settings.SettingsVersion.Value < 2)
        {
            // Version 1 defaulted restore points on for every apply.
            // Migrate that implicit default to off; users can opt in again.
            settings.CreateRestorePointBeforeApply = false;
            settings.SettingsVersion = 2;
            settings.Save();
        }
        return settings;
    }

    public void Save()
    {
        try { File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true })); }
        catch { /* non-fatal */ }
        try
        {
            File.WriteAllText(ConsentPath, JsonSerializer.Serialize(new ConsentFile
            {
                ConfirmAdvanced = ConfirmAdvanced,
                CreateRestorePointBeforeApply = CreateRestorePointBeforeApply,
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* non-fatal; Load fails closed without a readable consent file */ }
    }
}

/// <summary>
/// Remembers which option the app last applied per tweak. This is the fallback
/// state source for tweaks whose state cannot be read back from the registry,
/// and it is what survives restarts.
/// </summary>
public sealed class StateStore
{
    public sealed class Record
    {
        public string OptionLabel { get; set; } = "";
        public DateTimeOffset AppliedUtc { get; set; }
    }

    private readonly Dictionary<string, Record> _records;
    private readonly object _sync = new();
    private static string FilePath => Path.Combine(CatalogService.DataDir, "state.json");

    public StateStore()
    {
        _records = new Dictionary<string, Record>();
        try
        {
            if (File.Exists(FilePath))
            {
                var loaded = JsonSerializer.Deserialize<Dictionary<string, Record>>(File.ReadAllText(FilePath));
                if (loaded != null) _records = loaded;
            }
        }
        catch { /* start empty */ }
    }

    public Record? Get(string tweakId)
    {
        lock (_sync)
            return _records.TryGetValue(tweakId, out var record)
                ? new Record { OptionLabel = record.OptionLabel, AppliedUtc = record.AppliedUtc }
                : null;
    }

    public void Set(string tweakId, string optionLabel)
    {
        lock (_sync)
        {
            _records[tweakId] = new Record { OptionLabel = optionLabel, AppliedUtc = DateTimeOffset.UtcNow };
            Save();
        }
    }

    private void Save()
    {
        try { File.WriteAllText(FilePath, JsonSerializer.Serialize(_records, new JsonSerializerOptions { WriteIndented = true })); }
        catch { /* non-fatal */ }
    }
}
