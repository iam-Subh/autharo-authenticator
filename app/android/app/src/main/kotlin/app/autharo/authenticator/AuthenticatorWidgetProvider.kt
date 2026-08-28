package app.autharo.authenticator

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

data class HomeWidgetConfiguration(
    val enabled: Boolean,
    val entryId: String?,
    val title: String?,
)

object HomeWidgetStore {
    private const val PREFERENCES = "home_widget"
    private const val ENABLED = "enabled"
    private const val ENTRY_ID = "entry_id"
    private const val TITLE = "title"

    fun read(context: Context): HomeWidgetConfiguration {
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        return HomeWidgetConfiguration(
            enabled = preferences.getBoolean(ENABLED, false),
            entryId = preferences.getString(ENTRY_ID, null),
            title = preferences.getString(TITLE, null),
        )
    }

    fun write(context: Context, enabled: Boolean, entryId: String?, title: String?) {
        require(!enabled || !entryId.isNullOrBlank()) {
            "An enabled widget needs an entry"
        }
        val editor = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(ENABLED, enabled)
        if (enabled) {
            editor.putString(ENTRY_ID, entryId)
            editor.putString(TITLE, title?.take(120))
        } else {
            editor.remove(ENTRY_ID)
            editor.remove(TITLE)
        }
        check(editor.commit()) { "The widget setting could not be stored" }
        AuthenticatorWidgetProvider.updateAll(context)
    }
}

/**
 * Shows an account shortcut without copying an OTP secret or code into widget
 * storage. The user must unlock the application before the code is visible.
 */
class AuthenticatorWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray,
    ) {
        appWidgetIds.forEach { update(context, appWidgetManager, it) }
    }

    companion object {
        fun updateAll(context: Context) {
            val manager = AppWidgetManager.getInstance(context)
            val component = ComponentName(context, AuthenticatorWidgetProvider::class.java)
            manager.getAppWidgetIds(component).forEach { update(context, manager, it) }
        }

        private fun update(
            context: Context,
            manager: AppWidgetManager,
            widgetId: Int,
        ) {
            val configuration = HomeWidgetStore.read(context)
            val title = if (configuration.enabled) {
                configuration.title?.takeIf(String::isNotBlank)
                    ?: context.getString(R.string.widget_account)
            } else {
                context.getString(R.string.widget_not_configured)
            }
            val views = RemoteViews(context.packageName, R.layout.authenticator_widget)
            views.setTextViewText(R.id.widget_title, title)
            views.setTextViewText(
                R.id.widget_action,
                if (configuration.enabled) {
                    context.getString(R.string.widget_open_for_code)
                } else {
                    context.getString(R.string.widget_open_settings)
                },
            )

            val openApplication = Intent(context, MainActivity::class.java).apply {
                action = "app.autharo.authenticator.OPEN_WIDGET"
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pendingIntent = PendingIntent.getActivity(
                context,
                widgetId,
                openApplication,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            views.setOnClickPendingIntent(R.id.widget_root, pendingIntent)
            manager.updateAppWidget(widgetId, views)
        }
    }
}
