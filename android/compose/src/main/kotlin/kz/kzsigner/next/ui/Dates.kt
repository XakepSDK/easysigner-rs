package kz.kzsigner.next.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalConfiguration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.time.temporal.ChronoUnit
import java.util.Locale

@Composable
@ReadOnlyComposable
private fun locale(): Locale = LocalConfiguration.current.locales[0]

private fun day(ms: Long): LocalDate = Instant.ofEpochMilli(ms).atZone(ZoneId.systemDefault()).toLocalDate()

/** "12 November 2026", in the app's language. */
@Composable
@ReadOnlyComposable
fun longDate(ms: Long): String = DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG).withLocale(locale()).format(day(ms))

/** "11 December": the day and month, for dates within the year. */
@Composable
@ReadOnlyComposable
fun dayMonth(ms: Long): String = DateTimeFormatter.ofPattern("d MMMM", locale()).format(day(ms))

/** Whole days from today until [ms]'s day (0: today). */
fun daysUntil(ms: Long): Long = ChronoUnit.DAYS.between(LocalDate.now(), day(ms))
