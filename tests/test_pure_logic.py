from hackdev_dirbuster.fingerprint import analyze_response
from hackdev_dirbuster.scanner import (
    ScanResult,
    compute_body_hash,
    dedupe_results,
    is_directory_like,
    is_soft_404_match,
    normalize_body,
)
from hackdev_dirbuster.wordlists import (
    build_wordlist,
    merge_tech_wordlist,
    parse_extensions,
    parse_status_codes,
)


def test_build_wordlist_expands_extensions():
    result = build_wordlist(["config", "admin/"], ["php", ".bak"])
    assert "config" in result
    assert "config.php" in result
    assert "config.bak" in result
    assert "admin/" in result
    assert "admin/.php" not in result  # directory-like (trailing-slash) words never get extensions appended


def test_build_wordlist_skips_extension_fanout_for_words_with_extension_already():
    result = build_wordlist(["robots.txt"], ["php"])
    assert result.count("robots.txt") == 1
    assert "robots.txt.php" not in result


def test_build_wordlist_dedupes():
    result = build_wordlist(["admin", "admin"], [])
    assert result.count("admin") == 1


def test_merge_tech_wordlist_adds_known_tech_paths():
    merged = merge_tech_wordlist(["admin"], {"wordpress"})
    assert "wp-login.php" in merged
    assert "admin" in merged


def test_merge_tech_wordlist_no_tech_returns_original():
    assert merge_tech_wordlist(["admin"], set()) == ["admin"]


def test_merge_tech_wordlist_no_duplicates():
    merged = merge_tech_wordlist(["wp-login.php"], {"wordpress"})
    assert merged.count("wp-login.php") == 1


def test_normalize_body_strips_numbers_and_whitespace():
    a = normalize_body("Error 12345 occurred at  \n\n  2024-01-01")
    b = normalize_body("Error 99999 occurred at 2099-12-31")
    assert a == b


def test_compute_body_hash_same_for_structurally_identical_bodies():
    h1 = compute_body_hash("Request ID: 123456")
    h2 = compute_body_hash("Request ID: 987654")
    assert h1 == h2


def test_compute_body_hash_differs_for_different_bodies():
    assert compute_body_hash("foo") != compute_body_hash("bar")


def test_dedupe_results_collapses_threshold_group():
    results = [
        ScanResult(url=f"http://x/{i}", path=str(i), status=200, length=100, body_hash="same")
        for i in range(5)
    ]
    deduped, collapsed = dedupe_results(results, threshold=3)
    assert len(deduped) == 1
    assert deduped[0].likely_false_positive is True
    assert deduped[0].duplicate_count == 5
    assert collapsed == 4


def test_dedupe_results_leaves_small_groups_alone():
    results = [
        ScanResult(url="http://x/a", path="a", status=200, length=10, body_hash="h1"),
        ScanResult(url="http://x/b", path="b", status=200, length=10, body_hash="h2"),
    ]
    deduped, collapsed = dedupe_results(results, threshold=3)
    assert len(deduped) == 2
    assert collapsed == 0
    assert all(not r.likely_false_positive for r in deduped)


def test_is_soft_404_match_true_within_tolerance():
    assert is_soft_404_match(200, 105, baseline_status=200, baseline_length=100, tolerance=15) is True


def test_is_soft_404_match_false_outside_tolerance():
    assert is_soft_404_match(200, 200, baseline_status=200, baseline_length=100, tolerance=15) is False


def test_is_soft_404_match_false_different_status():
    assert is_soft_404_match(301, 100, baseline_status=200, baseline_length=100) is False


def test_is_soft_404_match_false_no_baseline():
    assert is_soft_404_match(200, 100, baseline_status=None, baseline_length=None) is False


def test_is_directory_like_redirect():
    assert is_directory_like(301, "/foo/", "", "foo") is True


def test_is_directory_like_html_no_extension():
    assert is_directory_like(200, None, "text/html", "admin") is True


def test_is_directory_like_false_for_file_extension():
    assert is_directory_like(200, None, "text/html", "config.php") is False


def test_analyze_response_detects_wordpress():
    result = analyze_response({}, "<html>see wp-content/uploads here</html>")
    assert "wordpress" in result.technologies


def test_analyze_response_detects_django_via_cookie():
    result = analyze_response({"Set-Cookie": "csrftoken=abc123"}, "")
    assert "django" in result.technologies


def test_analyze_response_detects_express_via_header():
    result = analyze_response({"X-Powered-By": "Express"}, "")
    assert "express" in result.technologies


def test_analyze_response_no_signals_no_technologies():
    result = analyze_response({}, "<html>just a plain page</html>")
    assert result.technologies == set()


def test_parse_extensions():
    assert parse_extensions("php, .html,js") == ["php", "html", "js"]
    assert parse_extensions(None) == []
    assert parse_extensions("") == []


def test_parse_status_codes_custom():
    assert parse_status_codes("200,301, 404") == {200, 301, 404}


def test_parse_status_codes_default_when_none():
    from hackdev_dirbuster.wordlists import DEFAULT_STATUS_CODES
    assert parse_status_codes(None) == set(DEFAULT_STATUS_CODES)
