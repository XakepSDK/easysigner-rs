package kz.kzsigner

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kz.kzsigner.core.Arrival
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.Desk
import kz.kzsigner.core.Guest
import kz.kzsigner.core.Meeting
import kz.kzsigner.core.MeetException
import kz.kzsigner.core.Nca
import kz.kzsigner.core.Outcome
import kz.kzsigner.core.Person
import kz.kzsigner.core.Signed
import kz.kzsigner.core.Turn
import kz.kzsigner.core.Vault
import kz.kzsigner.core.Visit

/** A PDF the lawyer chose to sign in person. */
class Paper(val name: String, val bytes: ByteArray)

/** Where the lawyer's phone is in a meeting. */
sealed interface Desking {
    /** The QR code is up, for the next signer. */
    data object Showing : Desking

    /** A signer's phone connected: they are reading and signing. */
    data class Here(val who: Person) : Desking

    /** Their signature came: Accept or Reject. */
    class Deciding(val who: Arrival, val answer: CompletableDeferred<Boolean>) : Desking
}

/**
 * Signing in person (docs/in-person-signing.md), both sides. The lawyer's phone holds the PDF
 * and shows one QR code per signer ([start], [decide], [finish]); a signer's phone scans it
 * ([join]) and signs there ([sign]). The core does the work; this keeps what the screens show.
 * [io] runs the core's blocking calls, [main] updates the state; [addresses]: this phone's
 * addresses on its networks, for the QR code.
 */
class InPersonFlow(
    private val scope: CoroutineScope,
    private val io: CoroutineContext,
    private val main: CoroutineContext,
    private val vault: () -> Vault?,
    private val nca: () -> Nca,
    private val addresses: () -> List<String> = ::localAddresses
) {
    // ---- the lawyer's phone ----

    /** The PDF to sign together, before the meeting starts. */
    var paper by mutableStateOf<Paper?>(null)

    var meeting by mutableStateOf<Meeting?>(null)
        private set

    /** The QR code shown now. */
    var qr by mutableStateOf<String?>(null)
        private set

    var desk by mutableStateOf<Desking>(Desking.Showing)
        private set

    /** Who signed so far, in order. */
    var signers by mutableStateOf<List<Person>>(emptyList())
        private set

    /** How the last signer's turn ended. */
    var last by mutableStateOf<Turn?>(null)
        private set

    /** Everyone signed: the finished document, which each signer now gets by scanning. */
    var finished by mutableStateOf<Signed?>(null)
        private set

    private var serving: Job? = null

    /**
     * Opens the meeting for [paper] with key [keyId] (its one prompt, or [password]), signing
     * first when [signFirst], and starts showing QR codes. Throws [kz.kzsigner.core.SignException].
     */
    suspend fun start(keyId: String, password: String?, prompt: ChipPrompt, lang: String, signFirst: Boolean) {
        val v = vault() ?: throw kz.kzsigner.core.SignException.Failed("no key vault")
        val p = paper ?: throw kz.kzsigner.core.SignException.Failed("no document")
        val m = withContext(io) { v.startMeeting(nca(), keyId, p.name, p.bytes, password, prompt, lang, signFirst) }
        meeting = m
        signers = m.signers()
        serve(m)
    }

    /** One signer after another until [close]: a new QR code for each. */
    private fun serve(m: Meeting) {
        serving = scope.launch(main) {
            while (true) {
                val code = withContext(io) { m.invite(addresses()) }
                qr = code
                desk = Desking.Showing
                val turn = withContext(io) { m.wait(DeskScreen()) }
                if (turn is Turn.Stopped) break
                last = turn
                signers = withContext(io) { m.signers() }
            }
        }
    }

    /** The core's calls about the signer at the phone; they come on its thread. */
    private inner class DeskScreen : Desk {
        override fun arrived(who: Person) {
            scope.launch(main) { desk = Desking.Here(who) }
        }

        override fun decide(who: Arrival): Boolean {
            val answer = CompletableDeferred<Boolean>()
            scope.launch(main) { desk = Desking.Deciding(who, answer) }
            return runBlocking { answer.await() }
        }
    }

    /** The lawyer's Accept or Reject. */
    fun decide(accept: Boolean) {
        (desk as? Desking.Deciding)?.answer?.complete(accept)
    }

    /** Everyone signed: the document gets NCA's archive timestamp. Throws SignException. */
    suspend fun finish(): Signed {
        val m = meeting ?: throw kz.kzsigner.core.SignException.Failed("no meeting")
        val s = withContext(io) { m.finish() }
        finished = s
        last = null
        return s
    }

    /** Leaves the meeting: a signer at the phone is cut off, nothing more is signed. */
    fun close() {
        (desk as? Desking.Deciding)?.answer?.complete(false)
        meeting?.stop()
        serving?.cancel()
        serving = null
        meeting = null
        paper = null
        qr = null
        signers = emptyList()
        last = null
        finished = null
        desk = Desking.Showing
    }

    // ---- a signer's phone ----

    /** The visit to the lawyer's phone, once connected. */
    var guest by mutableStateOf<Guest?>(null)
        private set

    var visit by mutableStateOf<Visit?>(null)
        private set

    /** The document to sign, read before signing. */
    var reading by mutableStateOf<kz.kzsigner.core.Reading?>(null)
        private set

    /** How signing ended: accepted or not. */
    var outcome by mutableStateOf<Outcome?>(null)
        private set

    /** The lawyer, and the document's name, from the request (for the screens after it). */
    var host by mutableStateOf<String?>(null)
        private set
    var title by mutableStateOf<String?>(null)
        private set

    /**
     * Connects to the phone that showed [code] and shows its request, as key [keyId]. [online]:
     * this phone has internet. Throws [MeetException].
     */
    suspend fun join(keyId: String, code: String, online: Boolean) {
        val v = vault() ?: throw MeetException.Failed("no key vault")
        leave()
        val g = withContext(io) { v.visit(nca(), keyId, code, online) }
        val what = g.visit()
        if (what is Visit.Sign) {
            host = what.lawyer
            title = what.title
            reading = withContext(io) { g.read() }
        }
        guest = g
        visit = what
    }

    /** Signs the request and waits for the lawyer's answer. Throws SignException. */
    suspend fun sign(password: String?, prompt: ChipPrompt, lang: String): Outcome {
        val v = vault() ?: throw kz.kzsigner.core.SignException.Failed("no key vault")
        val g = guest ?: throw kz.kzsigner.core.SignException.Failed("not connected")
        val o = withContext(io) { v.signVisit(g, password, prompt, lang) }
        outcome = o
        return o
    }

    /** Says no, or puts the visit away. */
    fun leave() {
        guest?.cancel()
        guest = null
        visit = null
        reading = null
        outcome = null
    }
}

/** This phone's IPv4 addresses on its Wi-Fi and hotspot networks (not mobile data). */
fun localAddresses(): List<String> = try {
    NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback }
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>()
        .filter { it.isSiteLocalAddress }
        .map { it.hostAddress.orEmpty() }
        .filter { it.isNotEmpty() }
        .distinct()
} catch (e: Exception) {
    emptyList()
}
