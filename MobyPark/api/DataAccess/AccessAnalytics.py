from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import sqlite3
from ..DBConnection import DBConnection

class AccessAnalytics:
    def __init__(self, conn: DBConnection):
        self.cursor = conn.cursor
        self.conn = conn.connection

    def get_occupancy_over_time(self, lot_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get occupancy data for a parking lot over time
        
        Args:
            lot_id: ID of the parking lot
            days: Number of days to look back (default: 30)
            
        Returns:
            List of occupancy data points with timestamp and occupancy percentage
        """
        try:
            query = """
            SELECT 
                strftime('%Y-%m-%d', started) as date,
                AVG(
                    CASE 
                        WHEN stopped IS NULL AND strftime('%Y-%m-%d', started) = strftime('%Y-%m-%d', 'now') 
                        THEN 1 
                        ELSE 0 
                    END
                ) as avg_occupancy
            FROM sessions
            WHERE parking_lot_id = ? 
                AND started >= date('now', ? || ' days')
            GROUP BY date
            ORDER BY date
            """
            self.cursor.execute(query, (lot_id, f"-{days}"))
            results = self.cursor.fetchall()
            
            # Convert results to list of dicts
            occupancy_data = [
                {
                    "date": row["date"], 
                    "occupancy_percentage": (row["avg_occupancy"] or 0) * 100
                } 
                for row in results
            ]
            
            # Fill in missing dates with 0% occupancy
            date_set = {data["date"] for data in occupancy_data}
            current_date = datetime.now().date()
            for i in range(days):
                date_str = (current_date - timedelta(days=i)).strftime('%Y-%m-%d')
                if date_str not in date_set:
                    occupancy_data.append({
                        "date": date_str,
                        "occupancy_percentage": 0
                    })
            
            # Sort by date
            occupancy_data.sort(key=lambda x: x["date"])
            
            return occupancy_data
            
        except Exception as e:
            print(f"Error in get_occupancy_over_time: {str(e)}")
            # Return empty data for now to prevent 500 errors
            return [{"date": (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d'), 
                    "occupancy_percentage": 0} 
                   for i in range(days, 0, -1)]

    def get_revenue(self, lot_id: str, start_date: str = None, end_date: str = None) -> Dict[str, Any]:
        """
        Get revenue data for a parking lot
        
        Args:
            lot_id: ID of the parking lot
            start_date: Start date in YYYY-MM-DD format (default: 30 days ago)
            end_date: End date in YYYY-MM-DD format (default: today)
            
        Returns:
            Dictionary containing total revenue and breakdown by payment type
        """
        try:
            if not start_date:
                start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            if not end_date:
                end_date = datetime.now().strftime('%Y-%m-%d')
            
            # Query to get revenue data
            query = """
            SELECT 
                payment_status as payment_method,
                COALESCE(SUM(cost), 0) as total_amount,
                COUNT(*) as transaction_count
            FROM sessions
            WHERE parking_lot_id = ?
                AND date(started) BETWEEN ? AND ?
                AND cost > 0
            GROUP BY payment_status
            """
            
            self.cursor.execute(query, (lot_id, start_date, end_date))
            results = self.cursor.fetchall()
            
            # Calculate totals
            total_revenue = sum(row['total_amount'] for row in results)
            total_transactions = sum(row['transaction_count'] for row in results)
            
            # Format breakdown
            breakdown = [
                {
                    "payment_method": row['payment_method'] or 'unknown',
                    "revenue": row['total_amount'],
                    "transactions": row['transaction_count']
                }
                for row in results
            ]
            
            return {
                "total_revenue": float(total_revenue),
                "total_transactions": total_transactions,
                "start_date": start_date,
                "end_date": end_date,
                "breakdown": breakdown
            }
            
        except Exception as e:
            print(f"Error in get_revenue: {str(e)}")
            return {
                "total_revenue": 0.0,
                "total_transactions": 0,
                "start_date": start_date or (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
                "end_date": end_date or datetime.now().strftime('%Y-%m-%d'),
                "breakdown": []
            }