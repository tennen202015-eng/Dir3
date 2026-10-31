package com.duwaini.shield

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit

data class DeviceCheck(
    val title: String,
    val ok: Boolean,
    val detail: String,
    val settingsAction: String?,
)

object DeviceChecks {
    fun run(ctx: Context): List<DeviceCheck> {
        val cr = ctx.contentResolver
        val list = mutableListOf<DeviceCheck>()

        val secure = ctx.getSystemService(KeyguardManager::class.java)?.isDeviceSecure ?: false
        list += DeviceCheck(
            "قفل الشاشة", secure,
            if (secure) "الجوال عليه رمز أو بصمة" else "مفيش قفل — أي حد يمسك الجوال يفتحه",
            Settings.ACTION_SECURITY_SETTINGS,
        )

        val patch = Build.VERSION.SECURITY_PATCH
        val days = try {
            ChronoUnit.DAYS.between(LocalDate.parse(patch), LocalDate.now())
        } catch (e: Exception) { -1L }
        val patchOk = days in 0..180
        list += DeviceCheck(
            "تحديث الحماية", patchOk,
            if (days < 0) "مش عارف أقرأ تاريخ آخر تحديث"
            else if (patchOk) "آخر تحديث حماية: $patch"
            else "آخر تحديث حماية من ${days / 30} شهر ($patch) — شوف لو في تحديث",
            Settings.ACTION_DEVICE_INFO_SETTINGS,
        )

        val versionOk = Build.VERSION.SDK_INT >= 30
        list += DeviceCheck(
            "إصدار أندرويد", versionOk,
            if (versionOk) "أندرويد ${Build.VERSION.RELEASE}"
            else "أندرويد ${Build.VERSION.RELEASE} قديم ومابقاش بياخد تحديثات حماية",
            null,
        )

        val dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        list += DeviceCheck(
            "خيارات المطوّر", !dev,
            if (dev) "مفتوحة — اقفلها لو مش محتاجها" else "مقفولة",
            Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS,
        )

        val adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        list += DeviceCheck(
            "تصحيح USB", !adb,
            if (adb) "مفتوح — أي كمبيوتر توصّله يقدر يتحكم في الجوال" else "مقفول",
            Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS,
        )

        val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
        val enc = dpm?.storageEncryptionStatus
        val encrypted = enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
            enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
            enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
        list += DeviceCheck(
            "تشفير التخزين", encrypted,
            if (encrypted) "بيانات الجوال متشفرة" else "التخزين مش متشفر",
            Settings.ACTION_SECURITY_SETTINGS,
        )

        val rooted = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/app/Superuser.apk", "/system/sd/xbin/su",
        ).any { File(it).exists() }
        list += DeviceCheck(
            "روت", !rooted,
            if (rooted) "الجوال متعمله روت — ده بيشيل حماية أندرويد الأساسية" else "مفيش روت",
            null,
        )

        return list
    }
}
