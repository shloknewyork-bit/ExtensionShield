from types import SimpleNamespace

from extension_shield.api.database import SupabaseDatabase, _escape_postgrest_like_term


class _FakeQuery:
    def __init__(self, response_data=None, execute_error=None):
        self.response_data = response_data or []
        self.execute_error = execute_error
        self.or_calls = []

    def select(self, *_args, **_kwargs):
        return self

    def eq(self, *_args, **_kwargs):
        return self

    def or_(self, filter_expr):
        self.or_calls.append(filter_expr)
        return self

    def order(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def execute(self):
        if self.execute_error is not None:
            raise self.execute_error
        return SimpleNamespace(data=self.response_data)


class _FakeClient:
    def __init__(self, queries):
        self._queries = list(queries)

    def table(self, _table_name):
        return self._queries.pop(0)


def _make_supabase_db(*queries):
    db = SupabaseDatabase.__new__(SupabaseDatabase)
    db.client = _FakeClient(queries)
    db.table_scan_results = "scan_results"
    return db


def test_escape_postgrest_like_term_escapes_wildcards_and_backslashes():
    assert _escape_postgrest_like_term(r"100%_match\value") == r"100\%\_match\\value"


def test_get_recent_scans_escapes_search_term_in_supabase_or_filter():
    query = _FakeQuery(
        response_data=[
            {
                "extension_id": "abcdefghijklmnopabcdefghijklmnop",
                "extension_name": "Safe Search",
                "updated_at": "2026-04-02T00:00:00+00:00",
            }
        ]
    )
    db = _make_supabase_db(query)

    db.get_recent_scans(limit=5, search=r"100%_match\value")

    assert query.or_calls[-1] == (
        r"extension_name.ilike.%100\%\_match\\value%,"
        r"extension_id.ilike.%100\%\_match\\value%"
    )


def test_get_recent_scans_fallback_escapes_search_term_in_supabase_or_filter():
    primary_query = _FakeQuery(execute_error=Exception("column visibility does not exist"))
    fallback_query = _FakeQuery(
        response_data=[
            {
                "extension_id": "abcdefghijklmnopabcdefghijklmnop",
                "extension_name": "Fallback Search",
                "updated_at": "2026-04-02T00:00:00+00:00",
            }
        ]
    )
    db = _make_supabase_db(primary_query, fallback_query)

    db.get_recent_scans(limit=5, search=r"100%_match\value")

    assert fallback_query.or_calls[-1] == (
        r"extension_name.ilike.%100\%\_match\\value%,"
        r"extension_id.ilike.%100\%\_match\\value%"
    )
