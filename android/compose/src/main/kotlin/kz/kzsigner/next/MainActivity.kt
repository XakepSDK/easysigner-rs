package kz.kzsigner.next

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import java.lang.ref.WeakReference
import kotlinx.coroutines.launch
import kz.kzsigner.next.ui.KzsignerTheme

/**
 * The one activity. AppCompat for the per-app language on Android 11 and 12 (13 and newer
 * have it built in); the screens are Compose.
 */
class MainActivity : AppCompatActivity() {
    private val model: KeysModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        current = WeakReference(this)
        enableEdgeToEdge()
        if (savedInstanceState == null) take(intent)
        chipTest(intent)
        setContent {
            KzsignerTheme {
                App(model, finish = ::finish)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        take(intent)
        chipTest(intent)
    }

    override fun onResume() {
        super.onResume()
        current = WeakReference(this)
        // a screen lock set in Settings meanwhile changes what a new key opens with
        model.refresh()
    }

    /**
     * A file opened with the app ("Open with kzsigner") or shared to it (Share in Telegram,
     * WhatsApp, a files app): a key file goes to Add key, anything else to Sign.
     */
    private fun take(intent: Intent?) {
        val uri = when (intent?.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
            else -> null
        } ?: return
        lifecycleScope.launch {
            val why = when (model.open(uri)) {
                Opened.TOO_BIG -> R.string.too_big
                Opened.UNREADABLE -> R.string.cant_read_file
                else -> return@launch
            }
            Toast.makeText(this@MainActivity, why, Toast.LENGTH_LONG).show()
        }
    }

    /** CI's check of the key chip ([ChipSelfTest]), on emulators only. */
    private fun chipTest(intent: Intent?) {
        if (intent?.getBooleanExtra("chiptest", false) == true && ChipSelfTest.emulator()) {
            ChipSelfTest.run(model.chip)
        }
    }

    companion object {
        private var current: WeakReference<Activity>? = null

        /** The activity on screen, for the key chip's prompt. */
        fun current(): Activity? = current?.get()
    }
}
