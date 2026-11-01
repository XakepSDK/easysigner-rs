# Fonts for the window

* `NotoSans-subset.ttf`: Noto Sans Regular cut down to Latin, Cyrillic (with the Kazakh letters)
  and common punctuation, 50 KB.
* `symbols.ttf`: the three symbols the window uses (✔ ✖ ⚠) from Noto Emoji, 1 KB.

Both are under the SIL Open Font License 1.1 (`OFL.txt`). They replace egui's bundled fonts, which
are about 650 KB. Made with fontTools:

    pyftsubset NotoSans-Regular.ttf --unicodes="U+0020-007E,U+00A0-00FF,U+0400-04FF,U+2010-2027,U+2030,U+2039,U+203A,U+20AC,U+20B8,U+2116,U+2122,U+2190-2193" \
        --no-hinting --desubroutinize --layout-features=kern --output-file=NotoSans-subset.ttf
    pyftsubset NotoEmoji-Regular.ttf --unicodes=2714,2716,26A0 --no-hinting --desubroutinize --output-file=symbols.ttf
