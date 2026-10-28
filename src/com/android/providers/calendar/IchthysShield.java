/*
 * Copyright (C) 2026 IchthysOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.providers.calendar;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Binder;
import android.os.Process;
import android.os.UserHandle;
import android.provider.Settings;
import android.provider.Telephony;
import android.telecom.TelecomManager;
import android.text.TextUtils;
import android.util.Log;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * IchthysOS: the calendar half of the contacts lockdown, plus the calendar write shield.
 *
 * <p>Like the contacts shield ({@code com.android.providers.contacts.IchthysShield}), this works
 * in the provider and leaves the permission grant alone: an app
 * may hold READ_CALENDAR, but unless the user trusts it, it sees the calendar of a phone that has
 * never had an account added: same columns, no calendars, no events. Its writes go the way of a
 * stock app-op denial ({@link android.content.ContentProvider#rejectInsert}, 0 rows changed).
 * Nothing about either answer marks the phone as IchthysOS.
 *
 * <p><b>Who is exempt.</b> The platform and the rest of the core system (app IDs below
 * {@link Process#FIRST_APPLICATION_UID}), the provider itself, preinstalled apps
 * ({@link ApplicationInfo#FLAG_SYSTEM} or {@link ApplicationInfo#FLAG_UPDATED_SYSTEM_APP}) and
 * platform-signed apps (the rule {@code com.android.bluetooth.ichthys.RadioPolicy} uses), the
 * default calendar app (the
 * {@link Intent#CATEGORY_APP_CALENDAR} handler, plus the ROM's own calendar app by name), the
 * default dialer, the default SMS app, and any package listed in the per-user
 * {@link Settings.Secure} key {@code ichthys_<feature>_allowed_pkgs} (comma-separated). For the
 * write feature the read allowlist counts too: an app the user gave real calendar access may also
 * change it. Ichthys Guard writes those keys; they are empty by default.
 *
 * <p><b>On unless switched off.</b> Each feature has a per-user {@link Settings.Secure} switch
 * {@code ichthys_<feature>_shield}; unset or non-zero is on, 0 is off.
 *
 * <p><b>Unresolvable means allowed.</b> If a setting or a default app cannot be read, the caller
 * is let through.
 *
 * <p>Keep in sync with {@code com.android.providers.contacts.IchthysShield}, which cannot share
 * code with this class because it ships in a different APK.
 */
public final class IchthysShield {

    private static final String TAG = "IchthysShield";

    /** Reading calendars and events. Restricted apps see an empty calendar. */
    public static final String FEATURE_CALENDAR = "calendar";

    /** Inserting, updating or deleting calendar data. Restricted apps' writes are no-ops. */
    public static final String FEATURE_CALENDAR_WRITE = "calendar_write";

    /**
     * Packages that own the calendar data or are the ROM's own calendar app. The user's default
     * calendar app, dialer and SMS app are resolved at runtime instead.
     */
    private static final List<String> ALWAYS_ALLOWED_PACKAGES =
            Collections.unmodifiableList(
                    Arrays.asList(
                            "com.android.providers.calendar",
                            "com.android.calendar",
                            // Etar, the calendar app IchthysOS ships.
                            "org.lineageos.etar"));

    private IchthysShield() {}

    /** The per-user {@link Settings.Secure} switch for {@code feature}. */
    public static String shieldSetting(String feature) {
        return "ichthys_" + feature + "_shield";
    }

    /** The per-user {@link Settings.Secure} allowlist for {@code feature}. */
    public static String allowedPackagesSetting(String feature) {
        return "ichthys_" + feature + "_allowed_pkgs";
    }

    /** Whether {@code packageName} running as {@code uid} is restricted for {@code feature}. */
    public static boolean isRestricted(
            Context context, String feature, int uid, String packageName) {
        if (context == null || UserHandle.getAppId(uid) < Process.FIRST_APPLICATION_UID
                || uid == Process.myUid()) {
            return false;
        }
        if (TextUtils.isEmpty(packageName)) {
            // Should not happen for an app UID; fail open like the rest of this class.
            return false;
        }
        final long token = Binder.clearCallingIdentity();
        try {
            if (!isEnabled(context, feature)) {
                return false;
            }
            // A name on the list counts only for the preinstalled app (com.android.calendar isn't
            // installed here; any sideloaded app could take that name).
            if ((ALWAYS_ALLOWED_PACKAGES.contains(packageName) && isSystemApp(context, uid))
                    || isUserAllowed(context, feature, packageName)) {
                return false;
            }
            if (FEATURE_CALENDAR_WRITE.equals(feature)
                    && isUserAllowed(context, FEATURE_CALENDAR, packageName)) {
                return false;
            }
            if (isSystemApp(context, uid)) {
                return false;
            }
            return !isDefaultApp(context, packageName);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    private static boolean isEnabled(Context context, String feature) {
        try {
            return Settings.Secure.getInt(
                            context.getContentResolver(), shieldSetting(feature), 1) != 0;
        } catch (RuntimeException e) {
            Log.w(TAG, "Failed to read " + shieldSetting(feature), e);
            return false;
        }
    }

    private static boolean isUserAllowed(Context context, String feature, String packageName) {
        final String key = allowedPackagesSetting(feature);
        final String allowed;
        try {
            allowed = Settings.Secure.getString(context.getContentResolver(), key);
        } catch (RuntimeException e) {
            Log.w(TAG, "Failed to read " + key, e);
            // Unresolvable means allowed.
            return true;
        }
        if (TextUtils.isEmpty(allowed)) {
            return false;
        }
        for (String pkg : allowed.split(",")) {
            if (packageName.equals(pkg.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether {@code uid} belongs to a preinstalled app ({@link ApplicationInfo#FLAG_SYSTEM} or
     * {@link ApplicationInfo#FLAG_UPDATED_SYSTEM_APP}) or to one signed with the platform key.
     * Call it with the calling identity cleared.
     */
    private static boolean isSystemApp(Context context, int uid) {
        try {
            final PackageManager pm = context
                    .createContextAsUser(UserHandle.getUserHandleForUid(uid), 0)
                    .getPackageManager();
            if (pm.checkSignatures(Process.SYSTEM_UID, uid) == PackageManager.SIGNATURE_MATCH) {
                return true;
            }
            final String[] packages = pm.getPackagesForUid(uid);
            if (packages == null) {
                return false;
            }
            for (String pkg : packages) {
                try {
                    final ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                    if ((info.flags & (ApplicationInfo.FLAG_SYSTEM
                            | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) {
                        return true;
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    // Raced with an uninstall; treat as not preinstalled.
                }
            }
            return false;
        } catch (RuntimeException e) {
            // Unresolvable means allowed.
            Log.w(TAG, "Cannot tell whether uid " + uid + " is a system app, allowing", e);
            return true;
        }
    }

    /** Whether {@code packageName} is the default calendar app, dialer or SMS app. */
    private static boolean isDefaultApp(Context context, String packageName) {
        try {
            if (packageName.equals(getDefaultCalendarPackage(context))) {
                return true;
            }
            final TelecomManager telecomManager = context.getSystemService(TelecomManager.class);
            if (telecomManager != null
                    && (packageName.equals(telecomManager.getDefaultDialerPackage())
                            || packageName.equals(telecomManager.getSystemDialerPackage()))) {
                return true;
            }
            if (packageName.equals(Telephony.Sms.getDefaultSmsPackage(context))) {
                return true;
            }
        } catch (RuntimeException e) {
            Log.w(TAG, "Cannot resolve the default apps, allowing " + packageName, e);
            return true;
        }
        return false;
    }

    /**
     * The package that opens for {@link Intent#CATEGORY_APP_CALENDAR} without asking: the one the
     * user picked as default, or the only calendar app installed. Null when the choice is open
     * (the resolver would be shown) or nothing handles it.
     */
    private static String getDefaultCalendarPackage(Context context) {
        final Intent intent =
                Intent.makeMainSelectorActivity(Intent.ACTION_MAIN, Intent.CATEGORY_APP_CALENDAR);
        final ResolveInfo info = context.getPackageManager()
                .resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY);
        if (info == null) {
            return null;
        }
        final ActivityInfo activityInfo = info.activityInfo;
        if (activityInfo == null || "android".equals(activityInfo.packageName)) {
            // The ResolverActivity: no default chosen.
            return null;
        }
        return activityInfo.packageName;
    }
}
