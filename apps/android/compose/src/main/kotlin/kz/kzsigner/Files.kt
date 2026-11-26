package kz.kzsigner

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream

/**
 * Files handed to other apps: a document to read in the app that opens it, the signed file
 * to send. They are written to the app's cache (shared/, see res/xml/file_paths.xml) and
 * passed as content:// links that only the receiving app may read.
 */
object Files {
    /** Writes [bytes] as cache/shared/[name]; the folder holds only the latest few. */
    fun share(context: Context, name: String, bytes: ByteArray): File {
        val dir = File(context.cacheDir, "shared").apply { mkdirs() }
        // last week's files go: they were handed over already
        val old = System.currentTimeMillis() - 7 * 24 * 3600 * 1000L
        dir.listFiles()?.filter { it.lastModified() < old }?.forEach { it.delete() }
        val f = File(dir, safe(name))
        f.writeBytes(bytes)
        return f
    }

    /**
     * Reads [input] whole when it holds at most [max] bytes; null when it holds more (only
     * [max] + 1 bytes are read to tell). InputStream.readNBytes is Android 13+.
     */
    fun readAtMost(input: InputStream, max: Int): ByteArray? {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() <= max) {
            val n = input.read(buf, 0, minOf(buf.size, max + 1 - out.size()))
            if (n == -1) break
            out.write(buf, 0, n)
        }
        return if (out.size() > max) null else out.toByteArray()
    }

    /** A file name with nothing that could leave the folder. */
    fun safe(name: String): String = name.replace(Regex("[\\\\/:*?\"<>|\\x00-\\x1f]"), "_").trim('.', ' ').ifEmpty { "document" }

    /** The media type of a file called [name]; [lookup] knows the common ones (the phone's list). */
    fun mime(name: String, lookup: (String) -> String? = { MimeTypeMap.getSingleton().getMimeTypeFromExtension(it) }): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "cms", "p7s", "sig" -> "application/pkcs7-signature"
            "p7m" -> "application/pkcs7-mime"
            "xml" -> "text/xml"
            else -> lookup(ext) ?: "application/octet-stream"
        }
    }

    private fun uri(context: Context, f: File) = FileProvider.getUriForFile(context, context.packageName + ".files", f)

    /** Opens the document in the app that reads its kind; false when the phone has none. */
    fun view(context: Context, name: String, bytes: ByteArray): Boolean {
        val f = share(context, name, bytes)
        val i = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri(context, f), mime(name))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        return try {
            context.startActivity(i)
            true
        } catch (e: ActivityNotFoundException) {
            false
        }
    }

    /** The share sheet with the signed file: Telegram, WhatsApp, mail, ... */
    fun send(context: Context, name: String, bytes: ByteArray) {
        val f = share(context, name, bytes)
        val u = uri(context, f)
        val i = Intent(Intent.ACTION_SEND)
            .setType(mime(name))
            .putExtra(Intent.EXTRA_STREAM, u)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        i.clipData = android.content.ClipData.newRawUri(name, u)
        context.startActivity(Intent.createChooser(i, null))
    }
}
