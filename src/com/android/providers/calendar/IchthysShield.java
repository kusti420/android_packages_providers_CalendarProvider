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

import android.Manifest;
import android.app.BroadcastOptions;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.os.Binder;
import android.os.Process;
import android.os.UserHandle;
import android.provider.Settings;
import android.provider.Telephony;
import android.telecom.TelecomManager;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.ichthys.guard.GuardEvent;
import com.android.internal.ichthys.guard.GuardShieldReporter;

import java.util.ArrayList;
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
 * ROM's own calendar app by name (preinstalled only), the
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
     * dialer and SMS app are resolved at runtime instead. There is no calendar role, so a
     * sideloaded calendar app reads the real calendar only from Guard's allow list (whatever
     * happens to resolve CATEGORY_APP_CALENDAR is no choice of the user).
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
            final boolean restricted = !isDefaultApp(context, packageName);
            if (restricted) {
                // IchthysOS: evidence for Guard ("Calendar shielded for X"); rate-limited there.
                GuardShieldReporter.note(uid, FEATURE_CALENDAR_WRITE.equals(feature)
                        ? GuardEvent.SHIELD_CALENDAR_WRITE : GuardEvent.SHIELD_CALENDAR, feature);
            }
            return restricted;
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

    /** Whether {@code packageName} is the default dialer or SMS app. */
    private static boolean isDefaultApp(Context context, String packageName) {
        try {
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
     * Marks an {@link android.provider.CalendarContract#ACTION_EVENT_REMINDER} the provider has
     * already passed on, so that its own receiver (which matches the same filter) drops it.
     */
    static final String EXTRA_REMINDER_PASSED_ON =
            "com.android.providers.calendar.ichthys.REMINDER_PASSED_ON";

    /**
     * The reminder alarm, addressed to the provider's own receiver only. On stock the alarm
     * itself is the implicit EVENT_REMINDER broadcast, with no permission: any app learns when
     * the user's events are due. {@link #passOnReminder} sends it on to the apps that may read
     * the calendar.
     */
    static Intent reminderAlarmIntent(Context context, long alarmTime) {
        final Intent intent = new Intent(android.provider.CalendarContract.ACTION_EVENT_REMINDER);
        intent.setData(android.content.ContentUris.withAppendedId(
                android.provider.CalendarContract.CONTENT_URI, alarmTime));
        intent.putExtra(android.provider.CalendarContract.CalendarAlerts.ALARM_TIME, alarmTime);
        intent.setFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        intent.setPackage(context.getPackageName());
        return intent;
    }

    /**
     * IchthysOS: pass a fired reminder alarm on as the stock EVENT_REMINDER broadcast, but only
     * to holders of READ_CALENDAR and, while the calendar shield is on, only to the apps it lets
     * read the calendar (the exempt calendar app, Etar, included). Like the SMS broadcast shield
     * in frameworks/opt/telephony: the manifest receivers are judged one by one, and the system
     * plus the user's allow list are named for their runtime receivers. Fails open (READ_CALENDAR
     * only) when the receivers cannot be resolved.
     */
    static void passOnReminder(Context context, Intent alarm) {
        final Intent reminder = new Intent(alarm);
        reminder.setComponent(null);
        reminder.setPackage(null);
        reminder.putExtra(EXTRA_REMINDER_PASSED_ON, true);
        reminder.addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        Bundle options = null;
        final long token = Binder.clearCallingIdentity();
        try {
            if (isEnabled(context, FEATURE_CALENDAR)) {
                final String[] included = reminderRecipients(context, reminder);
                if (included != null) {
                    if (included.length == 0) {
                        return;
                    }
                    final BroadcastOptions opts = BroadcastOptions.makeBasic();
                    opts.setIncludedPackages(included);
                    options = opts.toBundle();
                }
            }
        } finally {
            Binder.restoreCallingIdentity(token);
        }
        context.sendBroadcast(reminder, Manifest.permission.READ_CALENDAR, options);
    }

    /** The packages that may get a reminder, or null when they cannot be resolved. */
    private static String[] reminderRecipients(Context context, Intent reminder) {
        final String self = context.getPackageName();
        final List<String> included = new ArrayList<>();
        // The included packages filter runtime-registered receivers too, and system_server
        // registers its own as "android".
        included.add("android");
        try {
            final List<ResolveInfo> receivers =
                    context.getPackageManager().queryBroadcastReceivers(reminder, 0);
            for (ResolveInfo info : receivers) {
                if (info.activityInfo == null || info.activityInfo.applicationInfo == null) {
                    continue;
                }
                final String pkg = info.activityInfo.packageName;
                if (self.equals(pkg) || included.contains(pkg)) {
                    continue;
                }
                if (!isRestricted(context, FEATURE_CALENDAR,
                        info.activityInfo.applicationInfo.uid, pkg)) {
                    included.add(pkg);
                } else {
                    Log.i(TAG, "Withholding the event reminder from " + pkg);
                }
            }
            // Runtime-registered receivers can't be enumerated: name the allow list. A
            // "package:picked" entry sees only its picked events, not every reminder.
            final String allowed = Settings.Secure.getString(
                    context.getContentResolver(), allowedPackagesSetting(FEATURE_CALENDAR));
            if (!TextUtils.isEmpty(allowed)) {
                for (String entry : allowed.split(",")) {
                    final String pkg = entry.trim();
                    if (!pkg.isEmpty() && pkg.indexOf(':') < 0 && !self.equals(pkg)
                            && !included.contains(pkg)) {
                        included.add(pkg);
                    }
                }
            }
        } catch (RuntimeException e) {
            Log.w(TAG, "Cannot resolve the event reminder receivers, not filtering", e);
            return null;
        }
        return included.toArray(new String[0]);
    }
}
