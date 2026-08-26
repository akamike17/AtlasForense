namespace AtlasForense.Services;

internal static class SqliteRuntime
{
    private static readonly object Gate = new();
    private static bool _initialized;

    public static void Initialize()
    {
        if (_initialized) return;
        lock (Gate)
        {
            if (_initialized) return;
            SQLitePCL.raw.SetProvider(OperatingSystem.IsWindows()
                ? new SQLitePCL.SQLite3Provider_winsqlite3()
                : new SQLitePCL.SQLite3Provider_sqlite3());
            SQLitePCL.raw.FreezeProvider();
            _initialized = true;
        }
    }
}
