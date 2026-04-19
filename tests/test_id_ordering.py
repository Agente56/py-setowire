import unittest

from swarm import _is_local_id_lower


class TestIdOrdering(unittest.TestCase):
    def test_uses_truncated_8byte_id_for_compat(self):
        local_id = "1111111111111111aaaaaaaaaaaaaaaaaaaaaaaa"
        remote_id = "2222222222222222bbbbbbbbbbbbbbbbbbbbbbbb"
        self.assertTrue(_is_local_id_lower(local_id, remote_id, b"\x10", b"\x01"))
        self.assertFalse(_is_local_id_lower(remote_id, local_id, b"\x01", b"\x10"))

    def test_collision_on_truncated_id_falls_back_to_pubkey(self):
        # Same 16-hex prefix simulates a collision in the truncated on-wire id.
        local_id = "aaaaaaaaaaaaaaaa111111111111111111111111"
        remote_id = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
        local_pub = bytes.fromhex("01" * 32)
        remote_pub = bytes.fromhex("02" * 32)
        self.assertTrue(_is_local_id_lower(local_id, remote_id, local_pub, remote_pub))
        self.assertFalse(_is_local_id_lower(remote_id, local_id, remote_pub, local_pub))

    def test_collision_requires_valid_32byte_pubkeys(self):
        local_id = "aaaaaaaaaaaaaaaa111111111111111111111111"
        remote_id = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
        with self.assertRaises(ValueError):
            _is_local_id_lower(local_id, remote_id, None, bytes.fromhex("02" * 32))
        with self.assertRaises(ValueError):
            _is_local_id_lower(local_id, remote_id, bytes.fromhex("01" * 16), bytes.fromhex("02" * 32))


if __name__ == "__main__":
    unittest.main()
