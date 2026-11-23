package kz.kzsigner

import androidx.activity.compose.BackHandler
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import kz.kzsigner.ui.AboutScreen
import kz.kzsigner.ui.AddKeyScreen
import kz.kzsigner.ui.CantSignScreen
import kz.kzsigner.ui.CheckDetailsScreen
import kz.kzsigner.ui.CheckScreen
import kz.kzsigner.ui.Center
import kz.kzsigner.ui.HomeScreen
import kz.kzsigner.ui.KeysScreen
import kz.kzsigner.ui.PdfReader
import kz.kzsigner.ui.Reading
import kz.kzsigner.ui.Refusal
import kz.kzsigner.ui.SignScreen
import kz.kzsigner.ui.SignedScreen

private object Route {
    const val HOME = "home"
    const val SIGN = "sign"
    const val READ = "read"
    const val SIGNED = "signed"
    const val KEYS = "keys"
    const val ADD = "add"
    const val CANT_SIGN = "cant-sign"
    const val ABOUT = "about"
    const val CHECK = "check"
    const val DETAILS = "check-details"
}

/** Starts over at [route], with nothing to go back to. */
private fun NavHostController.restart(route: String) = navigate(route) {
    popUpTo(0) { inclusive = true }
}

/**
 * The app's screens. It opens on Home, or on Add key when there are no keys. A file shared
 * to the app (or opened with it) goes to Sign, or to Add key first when there is no key yet
 * (2c) and on to Sign once one is added; a key file goes to Add key.
 */
@Composable
fun App(model: KeysModel, finish: () -> Unit) {
    if (model.broken) {
        Center { Text(stringResource(R.string.cant_read_keys), style = MaterialTheme.typography.titleMedium) }
        return
    }
    val keys = model.keys ?: return
    val nav = rememberNavController()
    var refused by remember { mutableStateOf<Refusal?>(null) }
    var reading by remember { mutableStateOf<Reading?>(null) }
    // always Home: checking needs no key, and the key is asked for when signing first needs it
    val start = Route.HOME
    val hasKeys = model.keys?.keys?.isNotEmpty() == true

    // a key file opened with the app goes to Add key, wherever the app was
    LaunchedEffect(model.incoming) {
        if (model.incoming != null && nav.currentDestination?.route != Route.ADD) {
            nav.navigate(Route.ADD)
        }
    }
    // a document goes to Sign; without a key, to Add key first
    LaunchedEffect(model.document) {
        if (model.document == null || model.signed != null) return@LaunchedEffect
        val here = nav.currentDestination?.route
        if (model.keys?.keys?.isNotEmpty() == true) {
            if (here != Route.SIGN) nav.navigate(Route.SIGN) { popUpTo(Route.HOME) }
        } else if (here != Route.ADD) {
            nav.navigate(Route.ADD)
        }
    }

    // a file to check goes to Check
    LaunchedEffect(model.checking) {
        val here = nav.currentDestination?.route
        if (model.checking != null && here != Route.CHECK && here != Route.DETAILS) {
            nav.navigate(Route.CHECK)
        }
    }

    /** Back, or out of the app on its first screen. */
    val back: () -> Unit = { if (!nav.popBackStack()) finish() }
    /** Home, with nothing behind it. */
    val home: () -> Unit = {
        model.closeDocument()
        nav.restart(Route.HOME)
    }

    NavHost(nav, startDestination = start) {
        composable(Route.HOME) {
            HomeScreen(model, onKeys = { nav.navigate(if (hasKeys || keys.hidden) Route.KEYS else Route.ADD) })
        }
        composable(Route.SIGN) {
            val leave: () -> Unit = {
                model.closeDocument()
                if (!nav.popBackStack()) nav.restart(Route.HOME)
            }
            BackHandler(onBack = leave)
            SignScreen(
                model,
                onBack = leave,
                onRead = {
                    reading = it
                    nav.navigate(Route.READ)
                },
                onSigned = { nav.navigate(Route.SIGNED) { popUpTo(Route.SIGN) { inclusive = true } } },
                onCantSign = {
                    refused = it
                    nav.navigate(Route.CANT_SIGN)
                },
            )
        }
        composable(Route.READ) {
            val r = reading
            if (r != null) PdfReader(r.name, r.bytes, onBack = back)
        }
        composable(Route.SIGNED) {
            BackHandler(onBack = home)
            SignedScreen(model, onDone = home)
        }
        composable(Route.KEYS) {
            KeysScreen(
                model,
                onBack = back,
                onAdd = { nav.navigate(Route.ADD) },
                onAbout = { nav.navigate(Route.ABOUT) },
                onEmpty = { nav.restart(Route.HOME) },
            )
        }
        composable(Route.ADD) {
            AddKeyScreen(
                model,
                onBack = back,
                onAdded = {
                    when {
                        // 2c: straight back to the document
                        model.document != null && model.signed == null -> {
                            nav.restart(Route.HOME)
                            nav.navigate(Route.SIGN)
                        }
                        nav.previousBackStackEntry != null -> nav.popBackStack()
                        else -> nav.restart(Route.HOME)
                    }
                },
                onCantSign = {
                    refused = Refusal(it.reason, it.validFromMs, it.expiresMs)
                    nav.navigate(Route.CANT_SIGN)
                },
            )
        }
        composable(Route.CANT_SIGN) {
            val r = refused
            if (r != null) {
                CantSignScreen(
                    r.reason,
                    r.validFromMs,
                    r.expiresMs,
                    onBack = back,
                    onAddNew = {
                        nav.popBackStack(Route.ADD, inclusive = true)
                        nav.navigate(Route.ADD)
                    },
                )
            }
        }
        composable(Route.ABOUT) { AboutScreen(onBack = back) }
        composable(Route.CHECK) {
            val leave: () -> Unit = {
                model.checking = null
                model.checked = null
                if (!nav.popBackStack()) nav.restart(Route.HOME)
            }
            BackHandler(onBack = leave)
            CheckScreen(
                model,
                onBack = leave,
                onDetails = { nav.navigate(Route.DETAILS) },
                onRead = {
                    reading = it
                    nav.navigate(Route.READ)
                },
                onAnother = leave,
            )
        }
        composable(Route.DETAILS) { CheckDetailsScreen(model, onBack = back) }
    }
}
