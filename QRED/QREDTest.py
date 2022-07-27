import unittest
import QRED


class MyTestCase(unittest.TestCase):
    example_short_raw = "6ea43c09a808075f4cb01547501e09ba2265ddc5aa4b25affe26e67581dd3d54544de31d9c5cd4cf2a6481e5cb9c812b159d"

    def test_get_flags_returns_flags(self):
        flags = QRED.get_flags(self.example_short_raw)
        assert(flags == "6e")

    def test_can_extract_bit_from_flags(self):
        flags = QRED.get_flags(self.example_short_raw)
        bit = QRED.get_bit_from_flags(flags, 0x01)
        assert not bit

    def test_can_extract_delay_bit_from_flags(self):
        flags = QRED.get_flags(self.example_short_raw)
        delay_bit = QRED.get_delay_from_flags(flags)
        assert not delay_bit

    def test_can_extract_turned_on_delay_bit_from_flags(self):
        example_short_raw = "7ea43c09a808075f4cb01547501e09ba2265ddc5aa4b25affe26e67581dd3d54544de31d9c5cd4cf2a6481e5cb9c812b159d"
        flags = QRED.get_flags(example_short_raw)
        delay_bit = QRED.get_delay_from_flags(flags)
        assert delay_bit




if __name__ == '__main__':
    unittest.main()
