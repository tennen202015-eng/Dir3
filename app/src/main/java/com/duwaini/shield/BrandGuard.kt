package com.duwaini.shield

import java.util.Locale

/**
 * كشف التقليد: تطبيق أو رابط بيستخدم اسم بنك أو جهة حكومية أو تطبيق مشهور
 * وهو مش جاي من مصدره الرسمي.
 */
object BrandGuard {

    private class Brand(
        val name: String,
        /** كلمات تتدور جوه اسم التطبيق (بعد شيل المسافات) */
        val labelWords: List<String>,
        /** كلمات قصيرة لازم تكون كلمة مستقلة في اسم التطبيق */
        val labelTokens: List<String> = emptyList(),
        /** كلمات تتدور جوه اسم الموقع */
        val hostWords: List<String> = emptyList(),
        /** المواقع الرسمية */
        val officialDomains: List<String> = emptyList(),
        /** أسماء الحزم الرسمية المعروفة (للتطبيقات اللي بتتنزل من موقعها) */
        val officialPackages: List<String> = emptyList(),
    )

    private val BRANDS = listOf(
        Brand("مصرف الراجحي", listOf("rajhi", "الراجحي"), hostWords = listOf("rajhi"),
            officialDomains = listOf("alrajhibank.com.sa", "alrajhi-capital.sa")),
        Brand("البنك الأهلي", listOf("alahli", "الأهلي", "الاهلي"), listOf("snb", "nbe"),
            hostWords = listOf("alahli", "snb", "nbe"),
            officialDomains = listOf("alahli.com", "alahli.com.sa", "snb.com", "nbe.com.eg")),
        Brand("بنك الرياض", listOf("riyadbank", "بنكالرياض"), hostWords = listOf("riyadbank"),
            officialDomains = listOf("riyadbank.com")),
        Brand("مصرف الإنماء", listOf("alinma", "الإنماء", "الانماء"), hostWords = listOf("alinma"),
            officialDomains = listOf("alinma.com")),
        Brand("بنك البلاد", listOf("albilad", "بنكالبلاد"), hostWords = listOf("albilad"),
            officialDomains = listOf("bankalbilad.com")),
        Brand("بنك الجزيرة", listOf("aljazira", "بنكالجزيرة"), hostWords = listOf("aljazira"),
            officialDomains = listOf("bankaljazira.com")),
        Brand("ساب", listOf("بنكساب"), listOf("sab", "sabb"), hostWords = listOf("sabb"),
            officialDomains = listOf("sab.com", "sabb.com")),
        Brand("STC Pay", listOf("stcpay", "استيسي"), listOf("stc"), hostWords = listOf("stcpay", "stc"),
            officialDomains = listOf("stc.com.sa", "stcpay.com.sa", "stc.sa")),
        Brand("urpay", listOf("urpay"), hostWords = listOf("urpay"), officialDomains = listOf("urpay.com.sa")),
        Brand("أبشر", listOf("absher", "أبشر", "ابشر"), hostWords = listOf("absher"),
            officialDomains = listOf("absher.sa")),
        Brand("توكلنا", listOf("tawakkalna", "توكلنا"), hostWords = listOf("tawakkalna")),
        Brand("نفاذ", listOf("nafath", "نفاذ"), hostWords = listOf("nafath"), officialDomains = listOf("nafath.sa")),
        Brand("صحتي", listOf("sehhaty", "صحتي"), hostWords = listOf("sehhaty"), officialDomains = listOf("sehhaty.sa")),
        Brand("ناجز", listOf("najiz", "ناجز"), hostWords = listOf("najiz")),
        Brand("سداد", listOf("sadad", "سداد"), hostWords = listOf("sadad"), officialDomains = listOf("sadad.com")),
        Brand("البريد السعودي / سبل", listOf("saudipost", "البريدالسعودي"), listOf("spl", "سبل"),
            hostWords = listOf("saudipost", "splonline"), officialDomains = listOf("splonline.com.sa", "spl.com.sa")),
        Brand("أرامكس", listOf("aramex", "ارامكس", "أرامكس"), hostWords = listOf("aramex"),
            officialDomains = listOf("aramex.com")),
        Brand("سمسا", listOf("smsa", "سمسا"), hostWords = listOf("smsa"), officialDomains = listOf("smsaexpress.com")),
        Brand("CIB", listOf("cibegypt"), listOf("cib"), hostWords = listOf("cib", "cibeg"),
            officialDomains = listOf("cibeg.com")),
        Brand("بنك مصر", listOf("banquemisr", "بنكمصر"), hostWords = listOf("banquemisr"),
            officialDomains = listOf("banquemisr.com")),
        Brand("InstaPay", listOf("instapay", "انستاباي", "إنستاباي"), hostWords = listOf("instapay"),
            officialDomains = listOf("instapay.eg", "ipn.eg")),
        Brand("فوري", listOf("fawry"), hostWords = listOf("fawry"), officialDomains = listOf("fawry.com")),
        Brand("فودافون كاش", listOf("vodafonecash", "فودافونكاش"), hostWords = listOf("vodafone"),
            officialDomains = listOf("vodafone.com.eg", "vodafone.com")),
        Brand("واتساب", listOf("whatsapp", "واتساب", "واتسآب"), hostWords = listOf("whatsapp"),
            officialDomains = listOf("whatsapp.com", "whatsapp.net", "wa.me"),
            officialPackages = listOf("com.whatsapp", "com.whatsapp.w4b")),
        Brand("تيليجرام", listOf("telegram", "تيليجرام", "تلجرام"), hostWords = listOf("telegram"),
            officialDomains = listOf("telegram.org", "t.me", "telegram.me"),
            officialPackages = listOf("org.telegram.messenger", "org.telegram.messenger.web")),
        Brand("Google Chrome", listOf("chrome", "كروم"), officialPackages = listOf("com.android.chrome")),
        Brand("Google Play", listOf("googleplay", "playstore", "جوجلبلاي", "متجربلاي")),
        Brand("PayPal", listOf("paypal"), hostWords = listOf("paypal"), officialDomains = listOf("paypal.com")),
        Brand("Netflix", listOf("netflix", "نتفليكس"), hostWords = listOf("netflix"),
            officialDomains = listOf("netflix.com")),
    )

    /** الجهات الحكومية: أي موقع بينتهي بالامتدادات دي رسمي */
    private val OFFICIAL_SUFFIXES = listOf(".gov.sa", ".edu.sa", ".gov.eg", ".edu.eg")

    private fun normalize(s: String) =
        s.lowercase(Locale.ROOT).replace(Regex("[\\s\\-_.·•]+"), "")

    private fun tokens(s: String) =
        s.lowercase(Locale.ROOT).split(Regex("[^\\p{L}\\p{N}]+")).filter { it.isNotBlank() }.toSet()

    /** يرجع اسم الجهة اللي التطبيق بيقلّدها، أو null */
    fun impersonatedByApp(label: String, packageName: String): String? {
        val norm = normalize(label)
        val toks = tokens(label)
        val b = BRANDS.firstOrNull { b ->
            b.labelWords.any { norm.contains(normalize(it)) } || b.labelTokens.any { it in toks }
        } ?: return null
        if (packageName in b.officialPackages) return null
        return b.name
    }

    /** يرجع اسم الجهة اللي الموقع بيقلّدها، أو null */
    fun impersonatedByHost(host: String): String? {
        val h = host.lowercase(Locale.ROOT).removePrefix("www.")
        if (OFFICIAL_SUFFIXES.any { h.endsWith(it) }) return null
        val labels = h.split('.', '-').filter { it.isNotBlank() }
        for (b in BRANDS) {
            if (b.hostWords.isEmpty()) continue
            val hit = b.hostWords.any { w ->
                if (w.length <= 4) w in labels else labels.any { it.contains(w) }
            }
            if (!hit) continue
            val official = b.officialDomains.any { d -> h == d || h.endsWith(".$d") }
            if (!official) return b.name
        }
        return null
    }
}
