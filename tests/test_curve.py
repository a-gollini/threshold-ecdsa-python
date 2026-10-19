from threshold_ecdsa import curve


def test_generator_matches_known_public_key_for_private_key_one_and_two():
    assert curve.multiply_base(1).encode().hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    assert curve.multiply_base(2).encode().hex() == (
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )


def test_group_order_times_generator_is_infinity():
    assert curve.multiply(curve.G, curve.ORDER).is_infinity


def test_scalar_inverse():
    value = curve.random_scalar()

    assert curve.mod(value * curve.inverse(value)) == 1
