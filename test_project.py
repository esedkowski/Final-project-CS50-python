import pytest
from project import withdraw
from project import deposit_cash
from project import transfer

def test_withdraw():
    assert withdraw("Eryk", 20, 30) == 10
    with pytest.raises(TypeError) as exc_info:
        withdraw("Eryk", "Eryk", 30)
    assert withdraw("Eryk", 30, 20) == False

def test_deposit_cash():
    assert deposit_cash("Eryk", 10, 20) == 30
    assert deposit_cash("Eryk", 30, 20) == 50
    with pytest.raises(TypeError) as exc_info:
        deposit_cash("Eryk", "Eryk", 30)

def test_transfer():
    assert transfer("Eryk", 20, "Paula", 40) == False
    with pytest.raises(TypeError) as exc_info:
        transfer("Eryk", "Eryk", 30, 20)
    assert transfer("Eryk", 40, "Paula", 20) == False