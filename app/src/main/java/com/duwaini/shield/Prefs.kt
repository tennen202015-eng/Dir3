package com.duwaini.shield

import android.content.Context

class Prefs(ctx: Context) {
    private val sp = ctx.getSharedPreferences("shield", Context.MODE_PRIVATE)

    var vtKey: String
        get() = sp.getString("vt_key", "") ?: ""
        set(v) = sp.edit().putString("vt_key", v.trim()).apply()

    var autoScan: Boolean
        get() = sp.getBoolean("auto_scan", true)
        set(v) = sp.edit().putBoolean("auto_scan", v).apply()

    var lastScan: Long
        get() = sp.getLong("last_scan", 0L)
        set(v) = sp.edit().putLong("last_scan", v).apply()

    /** التطبيقات اللي اتشافت في آخر فحص — عشان نعرف الجديد */
    var knownPackages: Set<String>
        get() = sp.getStringSet("known", emptySet())?.toSet() ?: emptySet()
        set(v) = sp.edit().putStringSet("known", v).apply()

    /** تطبيقات المستخدم قال إنه واثق فيها */
    var trusted: Set<String>
        get() = sp.getStringSet("trusted", emptySet())?.toSet() ?: emptySet()
        set(v) = sp.edit().putStringSet("trusted", v).apply()
}
