"""Unit tests for price_manipulation_probe adapter. Mocks requests.request."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.price_manipulation_probe.execute import execute
from tradecraft.adapters.price_manipulation_probe.parse import parse


def _mock_response(status_code=200, text='{"ok":true}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_execute_requires_at_least_one_param():
    result = execute(target="https://shop.example.com/cart/1", body='{"item":"sku-1"}')
    assert result.error is not None
    assert "price_param" in result.error


def test_execute_rejects_invalid_baseline_body():
    result = execute(target="https://shop.example.com/cart/1", body="not-json", price_param="price")
    assert result.error is not None
    assert "invalid baseline" in result.error


def test_execute_quantity_only_generates_two_variants():
    with patch("tradecraft.adapters.price_manipulation_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://shop.example.com/cart/1",
            body='{"item":"sku-1","quantity":1}',
            quantity_param="quantity",
        )
    assert result.error is None
    variants = {a.variant for a in result.attempts}
    assert variants == {"quantity_negative", "quantity_overflow"}


def test_execute_price_only_generates_two_variants():
    with patch("tradecraft.adapters.price_manipulation_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://shop.example.com/cart/1",
            body='{"item":"sku-1","price":19.99}',
            price_param="price",
        )
    variants = {a.variant for a in result.attempts}
    assert variants == {"price_zero", "price_negative"}


def test_execute_both_params_caps_at_four():
    with patch("tradecraft.adapters.price_manipulation_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://shop.example.com/cart/1",
            body='{"item":"sku-1","quantity":1,"price":19.99}',
            price_param="price", quantity_param="quantity",
        )
    assert len(result.attempts) == 4
    variants = {a.variant for a in result.attempts}
    assert variants == {"quantity_negative", "quantity_overflow", "price_zero", "price_negative"}


def test_execute_injected_values_correct():
    with patch("tradecraft.adapters.price_manipulation_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://shop.example.com/cart/1",
            body='{"quantity":1,"price":19.99}',
            price_param="price", quantity_param="quantity",
        )
    neg_qty = next(a for a in result.attempts if a.variant == "quantity_negative")
    overflow_qty = next(a for a in result.attempts if a.variant == "quantity_overflow")
    zero_price = next(a for a in result.attempts if a.variant == "price_zero")
    assert neg_qty.injected_value == -1
    assert overflow_qty.injected_value == 999999999
    assert zero_price.injected_value == 0


def test_parse_confirms_variant_echoed_back():
    with patch("tradecraft.adapters.price_manipulation_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=200, text='{"price":0}')
        raw = execute(target="https://shop.example.com/cart/1", body='{"price":19.99}', price_param="price")
    result = parse(raw)
    confirmed = [a for a in result["attempts"] if a["classification"] == "accepted_confirmed"]
    assert len(confirmed) >= 1
    assert result["confirmed_accepted"] >= 1


def test_parse_rejected_validation_status():
    with patch("tradecraft.adapters.price_manipulation_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=422, text='{"error":"invalid price"}')
        raw = execute(target="https://shop.example.com/cart/1", body='{"price":19.99}', price_param="price")
    result = parse(raw)
    assert result["confirmed_accepted"] == 0
    assert all(a["classification"] == "rejected_validation" for a in result["attempts"])


def test_parse_top_level_error():
    result = parse(execute(target="https://shop.example.com/cart/1", body="bad", price_param="price"))
    assert "error" in result
