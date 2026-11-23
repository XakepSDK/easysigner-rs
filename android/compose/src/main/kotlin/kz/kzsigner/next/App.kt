package kz.kzsigner.next

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
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import kz.kzsigner.core.AddKeyException
import kz.kzsigner.next.ui.AboutScreen
import kz.kzsigner.next.ui.AddKeyScreen
import kz.kzsigner.next.ui.CantSignScreen
import kz.kzsigner.next.ui.Center
import kz.kzsigner.next.ui.KeysScreen

private object Route {
    const val KEYS = "keys"
    const val ADD = "add"
    const val CANT_SIGN = "cant-sign"
    const val ABOUT = "about"
}

/** Starts over at [route], with nothing to go back to. */
private fun NavHostController.restart(route: String) = navigate(route) {
    popUpTo(0) { inclusive = true }
}

/**
 * The app's screens. Until signing arrives (phase 3) it opens on Your keys, or on Add key
 * when there are none.
 */
@Composable
fun App(model: KeysModel, finish: () -> Unit) {
    if (model.broken) {
        Center { Text(stringResource(R.string.cant_read_keys), style = MaterialTheme.typography.titleMedium) }
        return
    }
    val keys = model.keys ?: return
    val nav = rememberNavController()
    var refused by remember { mutableStateOf<AddKeyException.KeyCantSign?>(null) }
    val start = remember { if (keys.keys.isEmpty() && !keys.hidden) Route.ADD else Route.KEYS }
    val here by nav.currentBackStackEntryAsState()

    // a key file opened with the app goes to Add key, wherever the app was
    LaunchedEffect(model.incoming) {
        if (model.incoming != null && here?.destination?.route != Route.ADD) {
            nav.navigate(Route.ADD)
        }
    }

    /** Back, or out of the app on its first screen. */
    val back: () -> Unit = { if (!nav.popBackStack()) finish() }

    NavHost(nav, startDestination = start) {
        composable(Route.KEYS) {
            KeysScreen(
                model,
                onBack = null,
                onAdd = { nav.navigate(Route.ADD) },
                onAbout = { nav.navigate(Route.ABOUT) },
                onEmpty = { nav.restart(Route.ADD) },
            )
        }
        composable(Route.ADD) {
            val hasKeys = model.keys?.keys?.isNotEmpty() == true
            AddKeyScreen(
                model,
                onBack = if (hasKeys || nav.previousBackStackEntry != null) back else null,
                onAdded = { nav.restart(Route.KEYS) },
                onCantSign = {
                    refused = it
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
                    onAddNew = { nav.popBackStack(Route.ADD, inclusive = true); nav.navigate(Route.ADD) },
                )
            }
        }
        composable(Route.ABOUT) { AboutScreen(onBack = back) }
    }
}
