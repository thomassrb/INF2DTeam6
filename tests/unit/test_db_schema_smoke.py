from MobyPark.api.DBConnection import DBConnection


def test_dbconnection_creates_core_tables(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    conn.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    table_names = {row[0] for row in conn.cursor.fetchall()}

    assert "users" in table_names
    assert "parking_lots" in table_names
    assert "parking_lots_coordinates" in table_names
    assert "vehicles" in table_names
    assert "sessions" in table_names
    assert "payments" in table_names
    assert "t_data" in table_names
    assert "reservations" in table_names

    conn.close_connection()
