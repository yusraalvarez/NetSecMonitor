#!/usr/bin/env python3
"""
Database initialization script for NetSecMonitor
Creates the SQLite database with the proper schema
"""

import sqlite3
import os
from pathlib import Path

# Database configuration
DB_PATH = "netsec_monitor.db"
SCHEMA_PATH = "database/schema.sql"

def init_database():
    """Initialize the database with schema"""
    print("🔧 Initializing NetSecMonitor database...")
    
    # Check if schema file exists
    if not os.path.exists(SCHEMA_PATH):
        print(f"❌ Error: Schema file not found at {SCHEMA_PATH}")
        return False
    
    # Create database connection
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Read and execute schema
        with open(SCHEMA_PATH, 'r') as f:
            schema_sql = f.read()
        
        cursor.executescript(schema_sql)
        conn.commit()
        
        # Verify tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print(f"✅ Database created successfully at {DB_PATH}")
        print(f"📊 Created {len(tables)} tables:")
        for table in tables:
            print(f"   - {table[0]}")
        
        # Create indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
        indexes = cursor.fetchall()
        print(f"🔍 Created {len(indexes)} indexes for query optimization")
        
        # Create views
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
        views = cursor.fetchall()
        print(f"👁️  Created {len(views)} views:")
        for view in views:
            print(f"   - {view[0]}")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def verify_database():
    """Verify database structure"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Test query
        cursor.execute("SELECT COUNT(*) FROM config;")
        config_count = cursor.fetchone()[0]
        print(f"\n✅ Database verification passed")
        print(f"📝 Configuration entries: {config_count}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("NetSecMonitor - Database Initialization")
    print("=" * 60)
    print()
    
    # Check if database already exists
    if os.path.exists(DB_PATH):
        response = input(f"⚠️  Database {DB_PATH} already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("❌ Initialization cancelled")
            exit(0)
        os.remove(DB_PATH)
        print("🗑️  Existing database removed")
    
    # Initialize database
    if init_database():
        if verify_database():
            print("\n✅ Database is ready for use!")
            print(f"📍 Location: {os.path.abspath(DB_PATH)}")
            print("\nNext steps:")
            print("  1. Run 'python monitor.py' to start monitoring")
            print("  2. Run 'python dashboard.py' to view the web interface")
        else:
            print("\n⚠️  Database created but verification failed")
    else:
        print("\n❌ Failed to initialize database")
