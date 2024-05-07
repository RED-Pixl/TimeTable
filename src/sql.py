import sqlite3

class SQL:
    def __init__(self, db_path):
        self.db_path = db_path
    
    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cur = self.conn.cursor()
        except sqlite3.Error as e:
            print(f"Error connecting to database: {e}")
    
    def close(self):
        if self.cur:
            self.cur.close()
        if self.conn:
            self.conn.close()


    '''
    USAGE: var.execute("INSERT QUERY", *args)
    '''
    def execute(self, sql, *args, **kwargs):
            self.connect()
            operation = sql.strip().split()[0].upper()
            
            try:
                self.cur.execute(sql, args)
                self.conn.commit()
                if operation == 'DELETE':
                    return self.cur.rowcount
                elif operation == 'INSERT':
                    return self.cur.lastrowid
                elif operation == 'SELECT':
                    columns = [col[0] for col in self.cur.description]
                    return [dict(zip(columns, row)) for row in self.cur.fetchall()]
                elif operation == 'UPDATE':
                    return self.cur.rowcount
                else:
                    raise ValueError("Operation not supported")
            except sqlite3.IntegrityError:
                raise ValueError("Value error occurred")
            except sqlite3.Error as e:
                raise RuntimeError(f"Error executing query: {e}")
            finally:
                self.close()

if __name__ == "__main__":

    # Tests
    print("SQL Module Imported")
