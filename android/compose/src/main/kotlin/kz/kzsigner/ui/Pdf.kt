package kz.kzsigner.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color as AColor
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.io.Closeable
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kz.kzsigner.R

/**
 * A PDF opened with Android's own renderer, from a private copy in the cache. Pages are
 * drawn one at a time (the renderer allows one open page). Null when Android can't read it
 * (a password-protected PDF, say): the app then shows the file's icon instead.
 */
class Pdf private constructor(private val file: File, private val fd: ParcelFileDescriptor, private val r: PdfRenderer) : Closeable {
    val pages: Int get() = r.pageCount

    /** Page [i] (from 0), [width] pixels wide, on white. */
    @Synchronized
    fun render(i: Int, width: Int): Bitmap? = try {
        r.openPage(i).use { p ->
            val h = (width.toLong() * p.height / p.width.coerceAtLeast(1)).toInt().coerceIn(1, 4 * width)
            val b = Bitmap.createBitmap(width, h, Bitmap.Config.ARGB_8888)
            b.eraseColor(AColor.WHITE)
            p.render(b, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
            b
        }
    } catch (e: Exception) {
        null
    }

    /** The page's height over its width. */
    @Synchronized
    fun ratio(i: Int): Float = try {
        r.openPage(i).use { it.height.toFloat() / it.width.coerceAtLeast(1) }
    } catch (e: Exception) {
        1.414f
    }

    @Synchronized
    override fun close() {
        try {
            r.close()
            fd.close()
        } catch (e: Exception) {
            // closed already
        }
        file.delete()
    }

    companion object {
        fun open(context: Context, bytes: ByteArray): Pdf? {
            val dir = File(context.cacheDir, "pdf").apply { mkdirs() }
            val f = File.createTempFile("doc", ".pdf", dir)
            return try {
                f.writeBytes(bytes)
                val fd = ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
                try {
                    Pdf(f, fd, PdfRenderer(fd))
                } catch (e: Exception) {
                    fd.close()
                    throw e
                }
            } catch (e: Exception) {
                f.delete()
                null
            }
        }
    }
}

/** The first page and the page count, for the Sign screen's preview. */
class PdfPreview(val pages: Int, val first: ImageBitmap?)

/** Reads [bytes] as a PDF off the main thread; null while reading or when it can't be read. */
@Composable
fun rememberPdfPreview(bytes: ByteArray?): PdfPreview? {
    val context = LocalContext.current
    val p by produceState<PdfPreview?>(null, bytes) {
        value = if (bytes == null) {
            null
        } else {
            withContext(Dispatchers.IO) {
                Pdf.open(context, bytes)?.use { pdf ->
                    PdfPreview(pdf.pages, if (pdf.pages > 0) pdf.render(0, 480)?.asImageBitmap() else null)
                }
            }
        }
    }
    return p
}

/** "Read it" for a PDF: every page, scrolled, inside the app. */
@Composable
fun PdfReader(name: String, bytes: ByteArray, onBack: () -> Unit) {
    val context = LocalContext.current
    val pdf = remember(bytes) { Pdf.open(context, bytes) }
    DisposableEffect(pdf) { onDispose { pdf?.close() } }
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.fillMaxSize().safeDrawingPadding()) {
            Box(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background)) {
                IconButton(onClick = onBack, modifier = Modifier.padding(4.dp)) {
                    Icon(painterResource(R.drawable.ic_back), stringResource(R.string.back))
                }
                Text(
                    name,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.MiddleEllipsis,
                    modifier = Modifier.padding(start = 60.dp, end = 16.dp, top = 16.dp, bottom = 16.dp)
                )
            }
            if (pdf == null) {
                Center { Body(stringResource(R.string.cant_show_pdf)) }
                return@Column
            }
            LazyColumn(
                contentPadding = PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(pdf.pages) { i -> PdfPage(pdf, i) }
            }
        }
    }
}

@Composable
private fun PdfPage(pdf: Pdf, i: Int) {
    val ratio = remember(pdf, i) { pdf.ratio(i) }
    val page by produceState<ImageBitmap?>(null, pdf, i) {
        value = withContext(Dispatchers.IO) { pdf.render(i, 1080)?.asImageBitmap() }
    }
    val m = Modifier.fillMaxWidth().aspectRatio(1f / ratio).background(Color.White)
    val p = page
    if (p == null) {
        Box(m)
    } else {
        Image(p, stringResource(R.string.page_n, i + 1, pdf.pages), m, contentScale = ContentScale.FillWidth)
    }
}
