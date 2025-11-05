from DBConnection import DBConnection
from storage_utils import load_json, write_json

connection = DBConnection("data/MobyParkData.db")

def migrate_users():
    ...