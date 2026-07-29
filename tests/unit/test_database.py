import os
import tempfile
import threading
import unittest

import database


class TestDatabasePooling(unittest.TestCase):

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        database.init_db(self.db_path)
        database.start_db_worker(self.db_path)

    def tearDown(self):
        database.stop_db_worker()
        database.close_thread_local_connections()
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_thread_local_connection_reuse(self):
        """Verify that execute_read reuses the thread-local connection on the same thread."""
        conn1 = database.get_read_connection()
        conn2 = database.get_read_connection()
        self.assertIs(conn1, conn2)

        results = database.execute_read("SELECT 1 as test")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["test"], 1)

    def test_multi_thread_connection_isolation(self):
        """Verify that separate threads get distinct thread-local connections."""
        connections = {}

        def _worker(thread_name):
            connections[thread_name] = database.get_read_connection()
            database.close_thread_local_connections()

        t1 = threading.Thread(target=_worker, args=("t1",))
        t2 = threading.Thread(target=_worker, args=("t2",))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertIn("t1", connections)
        self.assertIn("t2", connections)
        self.assertIsNot(connections["t1"], connections["t2"])

    def test_db_path_change_resets_connection(self):
        """Verify changing db_path invalidates old thread-local connection."""
        conn1 = database.get_read_connection()

        # Create a second temp DB
        fd2, path2 = tempfile.mkstemp()
        database.init_db(path2)

        conn2 = database.get_read_connection()
        self.assertIsNot(conn1, conn2)

        database.close_thread_local_connections()
        os.close(fd2)
        if os.path.exists(path2):
            os.unlink(path2)


if __name__ == "__main__":
    unittest.main()
