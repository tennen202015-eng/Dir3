package com.duwaini.shield

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** فحص تلقائي في الخلفية كل 6 ساعات — ينبهك لو اتثبت تطبيق جديد مشبوه */
class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val ctx = applicationContext
        val prefs = Prefs(ctx)
        val reports = try { AppScanner.scan(ctx) } catch (e: Exception) { return Result.retry() }
        val known = prefs.knownPackages
        val trusted = prefs.trusted

        val newRisky = reports.filter {
            it.packageName !in known && it.packageName !in trusted && it.level != RiskLevel.SAFE
        }
        val danger = reports.filter { it.level == RiskLevel.DANGER && it.packageName !in trusted }

        prefs.knownPackages = reports.map { it.packageName }.toSet()
        prefs.lastScan = System.currentTimeMillis()

        when {
            known.isNotEmpty() && newRisky.isNotEmpty() -> notify(
                ctx, "تطبيق جديد مشبوه",
                "${newRisky.first().label}: ${newRisky.first().reasons.firstOrNull() ?: "افتح درع وشوفه"}",
            )
            danger.isNotEmpty() -> notify(
                ctx, "في ${danger.size} تطبيق خطر على جوالك",
                danger.joinToString("، ") { it.label },
            )
        }
        return Result.success()
    }

    companion object {
        private const val WORK = "shield_scan"
        private const val CHANNEL = "alerts"

        fun schedule(ctx: Context, enabled: Boolean) {
            val wm = WorkManager.getInstance(ctx)
            if (enabled) {
                wm.enqueueUniquePeriodicWork(
                    WORK, ExistingPeriodicWorkPolicy.KEEP,
                    PeriodicWorkRequestBuilder<ScanWorker>(6, TimeUnit.HOURS).build(),
                )
            } else {
                wm.cancelUniqueWork(WORK)
            }
        }

        fun notify(ctx: Context, title: String, text: String) {
            if (Build.VERSION.SDK_INT >= 33 &&
                ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) return
            val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "تنبيهات الحماية", NotificationManager.IMPORTANCE_HIGH)
            )
            val open = PendingIntent.getActivity(
                ctx, 0, Intent(ctx, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val n = NotificationCompat.Builder(ctx, CHANNEL)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            nm.notify(1, n)
        }
    }
}
