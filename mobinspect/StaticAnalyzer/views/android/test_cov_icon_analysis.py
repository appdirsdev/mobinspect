# -*- coding: utf_8 -*-
"""Real-execution unit tests for icon_analysis (STRICT: NO mocks).

Every test drives the real functions with real files: real PNG bytes,
real binary Android XML (AXML) extracted from the bundled test APK/XAPK
samples, real SVG files through svgutils, and the real Django test DB
(append_scan_status issues a real ORM query).
"""
import io
import tempfile
import zipfile
from pathlib import Path

from django.test import TestCase

from mobinspect.StaticAnalyzer.views.android import icon_analysis as ia
from mobinspect.StaticAnalyzer.views.android.icon_analysis import (
    _search_folder,
    convert_axml_to_xml,
    convert_vector_to_svg,
    find_icon_path_zip,
    get_icon_apk,
    get_icon_apk_res,
    get_icon_from_src,
    get_icon_svg_from_xml,
    guess_icon_path,
    transform_svg,
)


REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'

# 1x1 transparent PNG (real, valid image bytes).
PNG_BYTES = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4'
    '890000000d49444154789c626001000000050001'
    '0d0a2db40000000049454e44ae426082')

SVG_TEXT = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
    '<rect width="10" height="10" fill="#000"/></svg>'
)


def _load_axml_samples():
    """Extract real binary AXML resources from the bundled XAPK sample."""
    z = zipfile.ZipFile(TEST_FILES / 'android_xapk.xapk')
    inner = z.read('com.tfg.samples.dynamicfeatures.ondemand.apk')
    iz = zipfile.ZipFile(io.BytesIO(inner))
    adaptive = iz.read('res/mipmap-anydpi-v26/ic_launcher.xml')
    vector = iz.read('res/drawable-v24/ic_launcher_foreground.xml')
    return adaptive, vector


ADAPTIVE_AXML, VECTOR_AXML = _load_axml_samples()

MD5 = 'a' * 32


class SearchFolderTests(TestCase):

    def test_finds_matching_files_recursively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.png').write_bytes(PNG_BYTES)
            sub = root / 'sub'
            sub.mkdir()
            (sub / 'b.png').write_bytes(PNG_BYTES)
            (root / 'c.txt').write_text('x')
            matches = _search_folder(str(root), '*.png')
            self.assertEqual(len(matches), 2)
            self.assertTrue(all(m.endswith('.png') for m in matches))

    def test_no_match_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_search_folder(tmp, '*.png'), [])


class GuessIconPathTests(TestCase):

    def test_direct_mipmap_hdpi_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            d = res / 'mipmap-hdpi'
            d.mkdir()
            icon = d / 'ic_launcher.png'
            icon.write_bytes(PNG_BYTES)
            self.assertEqual(guess_icon_path(str(res)), str(icon))

    def test_glob_ic_launcher_dot_star(self):
        # Not one of the 3 direct folders -> hit the 'ic_launcher.*' search.
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            d = res / 'mipmap-xhdpi'
            d.mkdir()
            icon = d / 'ic_launcher.webp'
            icon.write_bytes(PNG_BYTES)
            self.assertEqual(guess_icon_path(str(res)), str(icon))

    def test_glob_ic_launcher_prefix_fallback(self):
        # 'ic_launcher_round.png' matches 'ic_launcher*' but not
        # 'ic_launcher.*' -> exercises the third search loop.
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            d = res / 'drawable-night'
            d.mkdir()
            icon = d / 'ic_launcher_round.png'
            icon.write_bytes(PNG_BYTES)
            self.assertEqual(guess_icon_path(str(res)), str(icon))

    def test_no_icon_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(guess_icon_path(tmp), '')


class FindIconPathZipTests(TestCase):

    def _res(self, tmp):
        res = Path(tmp) / 'res'
        res.mkdir()
        return res

    def test_at_reference_with_mipmap_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            d = res / 'mipmap-hdpi'
            d.mkdir()
            icon = d / 'ic_launcher.png'
            icon.write_bytes(PNG_BYTES)
            out = find_icon_path_zip(
                MD5, str(res), ['@mipmap/ic_launcher'])
            self.assertEqual(out, str(icon))

    def test_res_prefix_exact_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            d = res / 'mipmap-hdpi'
            d.mkdir()
            icon = d / 'ic_launcher.png'
            icon.write_bytes(PNG_BYTES)
            out = find_icon_path_zip(
                MD5, str(res), ['res/mipmap-hdpi/ic_launcher.png'])
            self.assertEqual(out, str(icon))

    def test_res_prefix_appends_png(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            d = res / 'mipmap-hdpi'
            d.mkdir()
            icon = d / 'ic_launcher.png'
            icon.write_bytes(PNG_BYTES)
            # No extension -> function appends .png and matches.
            out = find_icon_path_zip(
                MD5, str(res), ['res/mipmap-hdpi/ic_launcher'])
            self.assertEqual(out, str(icon))

    def test_global_filename_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            deep = res / 'deep'
            deep.mkdir()
            target = deep / 'mylogo'
            target.write_bytes(PNG_BYTES)
            out = find_icon_path_zip(MD5, str(res), ['weird/mylogo'])
            self.assertEqual(out, str(target))

    def test_falls_back_to_guess_icon_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            d = res / 'mipmap-hdpi'
            d.mkdir()
            icon = d / 'ic_launcher.png'
            icon.write_bytes(PNG_BYTES)
            # Reference resolves to nothing -> guess_icon_path fallback.
            out = find_icon_path_zip(
                MD5, str(res), ['@mipmap/does_not_exist'])
            self.assertEqual(out, str(icon))

    def test_res_prefix_appends_png_second_check(self):
        # Trailing chars survive strip('/res'); exact miss, +'.png' hits.
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            # dir must not start with r/e/s (strip('/res') eats those).
            d = res / 'dir1'
            d.mkdir()
            target = d / 'logo.q.png'
            target.write_bytes(PNG_BYTES)
            out = find_icon_path_zip(MD5, str(res), ['res/dir1/logo.q'])
            self.assertEqual(out, str(target))

    def test_filename_png_double_suffix_search(self):
        # last segment ends '.png' -> code appends '.png' again then
        # searches for the doubled name.
        with tempfile.TemporaryDirectory() as tmp:
            res = self._res(tmp)
            d = res / 'deep'
            d.mkdir()
            target = d / 'bar.png.png'
            target.write_bytes(PNG_BYTES)
            out = find_icon_path_zip(MD5, str(res), ['foo/bar.png'])
            self.assertEqual(out, str(target))

    def test_exception_branch_returns_none(self):
        # None is not iterable -> TypeError caught -> returns None.
        self.assertIsNone(find_icon_path_zip(MD5, '/nope', None))


class GetIconFromSrcTests(TestCase):

    def test_eclipse_layout_copies_icon(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp) / 'app'
            res = app_dir / 'res' / 'mipmap-hdpi'
            res.mkdir(parents=True)
            (res / 'ic_launcher.png').write_bytes(PNG_BYTES)
            dwd = Path(tmp) / 'dwd'
            dwd.mkdir()
            app_dic = {'md5': MD5, 'app_dir': app_dir.as_posix()}
            with self.settings(DWD_DIR=dwd.as_posix()):
                get_icon_from_src(app_dic, ['@mipmap/ic_launcher'])
            self.assertEqual(app_dic['icon_path'], MD5 + '-icon.png')
            self.assertTrue((dwd / app_dic['icon_path']).exists())

    def test_studio_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp) / 'app'
            res = app_dir / 'app' / 'src' / 'main' / 'res' / 'mipmap-hdpi'
            res.mkdir(parents=True)
            (res / 'ic_launcher.png').write_bytes(PNG_BYTES)
            dwd = Path(tmp) / 'dwd'
            dwd.mkdir()
            app_dic = {'md5': MD5, 'app_dir': app_dir.as_posix()}
            with self.settings(DWD_DIR=dwd.as_posix()):
                get_icon_from_src(app_dic, ['@mipmap/ic_launcher'])
            self.assertEqual(app_dic['icon_path'], MD5 + '-icon.png')

    def test_no_res_dir_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp) / 'app'
            app_dir.mkdir()
            app_dic = {'md5': MD5, 'app_dir': app_dir.as_posix()}
            self.assertIsNone(get_icon_from_src(app_dic, ['@mipmap/x']))
            self.assertNotIn('icon_path', app_dic)


class GetIconApkResTests(TestCase):

    def _base(self, tmp, **extra):
        d = {
            'md5': MD5,
            'app_dir': Path(tmp).as_posix(),
            'tools_dir': (Path(tmp) / 'tools').as_posix(),
        }
        d.update(extra)
        return d

    def test_res_exists_no_icon_guesses_png(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp) / 'res' / 'mipmap-hdpi'
            res.mkdir(parents=True)
            icon = res / 'ic_launcher.png'
            icon.write_bytes(PNG_BYTES)
            out = get_icon_apk_res(self._base(tmp))
            self.assertTrue(out.endswith('ic_launcher.png'))

    def test_png_icon_easy_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            rel = 'res/mipmap-hdpi-v4/ic_launcher.png'
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True)
            p.write_bytes(PNG_BYTES)
            out = get_icon_apk_res(
                self._base(tmp, androguard_apk_icon=rel))
            self.assertEqual(out, p.as_posix())

    def test_apk_features_icon_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            rel = 'res/mipmap-mdpi-v4/ic_launcher.png'
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True)
            p.write_bytes(PNG_BYTES)
            out = get_icon_apk_res(self._base(
                tmp, apk_features={'application_icon': rel}))
            self.assertEqual(out, p.as_posix())

    def test_path_traversal_icon_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp) / 'res' / 'mipmap-hdpi'
            res.mkdir(parents=True)
            (res / 'ic_launcher.png').write_bytes(PNG_BYTES)
            # Absolute path triggers path-traversal detection -> ignored,
            # then falls back to guessing from res.
            out = get_icon_apk_res(self._base(
                tmp, androguard_apk_icon='/etc/passwd'))
            self.assertTrue(out.endswith('ic_launcher.png'))

    def test_reserved_file_name_becomes_conflict_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp) / 'res' / 'mipmap-hdpi'
            res.mkdir(parents=True)
            (res / 'ic_launcher.png').write_bytes(PNG_BYTES)
            # 'AndroidManifest.xml' is reserved -> prefixed with _conflict_,
            # ends with .xml -> XML handling path -> conversion fails on the
            # missing file -> ultimately guesses the real png.
            out = get_icon_apk_res(self._base(
                tmp, androguard_apk_icon='AndroidManifest.xml'))
            self.assertTrue(out.endswith('ic_launcher.png'))

    def test_adaptive_icon_xml_real_axml(self):
        with tempfile.TemporaryDirectory() as tmp:
            rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True)
            p.write_bytes(ADAPTIVE_AXML)
            # Provide a fallback png so a valid icon is still returned.
            gd = Path(tmp) / 'res' / 'mipmap-hdpi'
            gd.mkdir(parents=True)
            (gd / 'ic_launcher.png').write_bytes(PNG_BYTES)
            out = get_icon_apk_res(self._base(
                tmp, androguard_apk_icon=rel))
            # convert_axml_to_xml decodes real <adaptive-icon> -> returns
            # False -> apktool_res path taken; final fallback is the png.
            self.assertTrue(out.endswith('ic_launcher.png'))
            # The binary xml was rewritten to text containing adaptive-icon.
            self.assertIn('<adaptive-icon', p.read_text('utf8', 'ignore'))

    def test_vector_xml_with_existing_svg(self):
        # Real vector AXML -> convert returns True; a sibling .svg already
        # present -> ipath.exists() branch -> icon_src is the svg.
        with tempfile.TemporaryDirectory() as tmp:
            rel = 'res/drawable/ic_fg.xml'
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True)
            p.write_bytes(VECTOR_AXML)
            (p.parent / 'ic_fg.svg').write_text(SVG_TEXT)
            out = get_icon_apk_res(self._base(
                tmp, androguard_apk_icon=rel))
            self.assertTrue(out.endswith('ic_fg.svg'))

    def test_guessed_xml_icon_yields_empty(self):
        # res has only ic_launcher.xml (text) -> guessed as icon -> XML
        # path -> conversion fails -> no svg -> icon_src ends .xml -> ''.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / 'res' / 'mipmap-hdpi'
            d.mkdir(parents=True)
            (d / 'ic_launcher.xml').write_text('<vector/>')
            out = get_icon_apk_res(self._base(tmp))
            self.assertEqual(out, '')

    def test_outer_exception_returns_empty(self):
        # Missing 'app_dir' raises inside try -> caught -> ''.
        self.assertEqual(get_icon_apk_res({'md5': MD5}), '')

    def test_no_icon_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            # res exists but contains no ic_launcher.* -> empty result.
            (Path(tmp) / 'res' / 'values').mkdir(parents=True)
            out = get_icon_apk_res(self._base(tmp))
            self.assertEqual(out, '')

    def test_apktool_res_fallback_copytree(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk_res = Path(tmp) / 'apktool_out' / 'res' / 'mipmap-hdpi'
            apk_res.mkdir(parents=True)
            (apk_res / 'ic_launcher.png').write_bytes(PNG_BYTES)
            # No top-level res -> copytree from apktool_out then guess.
            out = get_icon_apk_res(self._base(tmp))
            self.assertTrue(out.endswith('ic_launcher.png'))
            self.assertTrue((Path(tmp) / 'res').exists())


class GetIconApkTests(TestCase):

    def test_copies_png_to_downloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            rel = 'res/mipmap-hdpi-v4/ic_launcher.png'
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True)
            p.write_bytes(PNG_BYTES)
            dwd = Path(tmp) / 'dwd'
            dwd.mkdir()
            app_dic = {
                'md5': MD5,
                'app_dir': Path(tmp).as_posix(),
                'tools_dir': (Path(tmp) / 'tools').as_posix(),
                'androguard_apk_icon': rel,
            }
            with self.settings(DWD_DIR=dwd.as_posix()):
                get_icon_apk(app_dic)
            self.assertEqual(app_dic['icon_path'], MD5 + '-icon.png')
            self.assertTrue((dwd / app_dic['icon_path']).exists())

    def test_outer_exception_swallowed(self):
        # Empty app_dic: icon_path set to '' then get_icon_apk_res raises
        # KeyError on md5 -> caught by get_icon_apk -> icon_path stays ''.
        app_dic = {}
        get_icon_apk(app_dic)
        self.assertEqual(app_dic['icon_path'], '')

    def test_no_icon_leaves_empty_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'res' / 'values').mkdir(parents=True)
            dwd = Path(tmp) / 'dwd'
            dwd.mkdir()
            app_dic = {
                'md5': MD5,
                'app_dir': Path(tmp).as_posix(),
                'tools_dir': (Path(tmp) / 'tools').as_posix(),
            }
            with self.settings(DWD_DIR=dwd.as_posix()):
                get_icon_apk(app_dic)
            self.assertEqual(app_dic['icon_path'], '')


class TransformSvgTests(TestCase):

    def test_real_transform_produces_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fg = Path(tmp) / 'fg.svg'
            bg = Path(tmp) / 'bg.svg'
            fg.write_text(SVG_TEXT)
            bg.write_text(SVG_TEXT)
            out = Path(tmp) / 'merged.svg'
            res = transform_svg(fg.as_posix(), bg.as_posix(), out)
            self.assertEqual(res, out.as_posix())
            self.assertTrue(out.exists())

    def test_bad_input_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'merged.svg'
            self.assertIsNone(transform_svg(None, None, out))


class GetIconSvgFromXmlTests(TestCase):

    def test_primary_foreground_background_transform(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            xdir = app_dir / 'apktool_out' / 'res' / 'mipmap-anydpi-v26'
            xdir.mkdir(parents=True)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            xml = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<adaptive-icon xmlns:android='
                '"http://schemas.android.com/apk/res/android">'
                '<background android:drawable="@drawable/ic_bg"/>'
                '<foreground android:drawable="@drawable/ic_fg"/>'
                '</adaptive-icon>'
            )
            (app_dir / 'apktool_out' / icon_rel).write_text(xml)
            (xdir / 'ic_fg.svg').write_text(SVG_TEXT)
            (xdir / 'ic_bg.svg').write_text(SVG_TEXT)
            out = get_icon_svg_from_xml(app_dir, icon_rel)
            self.assertTrue(out.endswith('.svg'))
            self.assertTrue(Path(out).exists())

    def test_fallback_drawable_both_svgs(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            # Primary xml lacks foreground/background -> IndexError ->
            # fallback searches apktool_out/res/drawable.
            xpath = app_dir / 'apktool_out' / icon_rel
            xpath.parent.mkdir(parents=True)
            xpath.write_text('<adaptive-icon></adaptive-icon>')
            drawable = app_dir / 'apktool_out' / 'res' / 'drawable'
            drawable.mkdir(parents=True)
            (drawable / 'ic_launcher_foreground.svg').write_text(SVG_TEXT)
            (drawable / 'ic_launcher_background.svg').write_text(SVG_TEXT)
            out = get_icon_svg_from_xml(app_dir, icon_rel)
            self.assertTrue(out.endswith('ic_launcher.svg'))
            self.assertTrue(Path(out).exists())

    def test_fallback_single_svg_returns_random(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            xpath = app_dir / 'apktool_out' / icon_rel
            xpath.parent.mkdir(parents=True)
            xpath.write_text('<adaptive-icon></adaptive-icon>')
            drawable = app_dir / 'apktool_out' / 'res' / 'drawable'
            drawable.mkdir(parents=True)
            only = drawable / 'some_icon.svg'
            only.write_text(SVG_TEXT)
            out = get_icon_svg_from_xml(app_dir, icon_rel)
            self.assertEqual(out, only.as_posix())

    def test_fallback_no_drawable_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            xpath = app_dir / 'apktool_out' / icon_rel
            xpath.parent.mkdir(parents=True)
            xpath.write_text('<adaptive-icon></adaptive-icon>')
            self.assertIsNone(get_icon_svg_from_xml(app_dir, icon_rel))


class ConvertAxmlToXmlTests(TestCase):

    def test_adaptive_icon_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            icon_rel = 'ic_launcher.xml'
            (Path(tmp) / icon_rel).write_bytes(ADAPTIVE_AXML)
            res = convert_axml_to_xml(Path(tmp), icon_rel)
            self.assertIs(res, False)
            # Rewritten to human-readable XML with adaptive-icon.
            self.assertIn(
                '<adaptive-icon',
                (Path(tmp) / icon_rel).read_text('utf8', 'ignore'))

    def test_vector_returns_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            icon_rel = 'ic_fg.xml'
            (Path(tmp) / icon_rel).write_bytes(VECTOR_AXML)
            res = convert_axml_to_xml(Path(tmp), icon_rel)
            self.assertIs(res, True)
            self.assertIn(
                '<vector',
                (Path(tmp) / icon_rel).read_text('utf8', 'ignore'))

    def test_missing_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(convert_axml_to_xml(Path(tmp), 'nope.xml'))


class ConvertVectorToSvgTests(TestCase):
    """Drives the real subprocess assembly; java may be absent, in which
    case the exception is caught. Either way the code path executes."""

    def test_direct_vector_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / 'res' / 'values').mkdir(parents=True)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            p = app_dir / icon_rel
            p.parent.mkdir(parents=True)
            p.write_text('<vector/>')
            tools = app_dir / 'tools'
            tools.mkdir()
            # Should not raise regardless of java availability.
            convert_vector_to_svg(
                app_dir, tools.as_posix(), icon_rel, apktool_res=False)

    def test_apktool_res_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            drawable = app_dir / 'apktool_out' / 'res' / 'drawable'
            drawable.mkdir(parents=True)
            (drawable / 'ic_launcher_foreground.xml').write_text('<vector/>')
            (app_dir / 'apktool_out' / 'res' / 'values').mkdir(parents=True)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            tools = app_dir / 'tools'
            tools.mkdir()
            convert_vector_to_svg(
                app_dir, tools.as_posix(), icon_rel, apktool_res=True)

    def test_user_vd2svg_binary_branch(self):
        # A configured, existing VD2SVG_BINARY is used directly.
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / 'res' / 'values').mkdir(parents=True)
            icon_rel = 'res/mipmap-anydpi-v26/ic_launcher.xml'
            p = app_dir / icon_rel
            p.parent.mkdir(parents=True)
            p.write_text('<vector/>')
            userbin = app_dir / 'vd2svg.jar'
            userbin.write_bytes(b'not a real jar')
            with self.settings(VD2SVG_BINARY=userbin.as_posix()):
                convert_vector_to_svg(
                    app_dir, (app_dir / 'tools').as_posix(),
                    icon_rel, apktool_res=False)
