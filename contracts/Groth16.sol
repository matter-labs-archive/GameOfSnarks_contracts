pragma solidity ^0.4.24;

library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point p) pure internal returns (G1Point) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G2Point p) pure internal returns (G2Point) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        return G2Point([p.X[0], q - (p.X[1] % q)], [p.Y[0], q - (p.Y[1] % q)]);
    }
    
    /// @return the sum of two points of G1
    function addition(G1Point p1, G1Point p2) internal view returns (G1Point r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas, 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }
    /// @return the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point p, uint s) internal view returns (G1Point r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas, 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] p1, G2Point[] p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point a1, G2Point a2, G1Point b1, G2Point b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point a1, G2Point a2,
            G1Point b1, G2Point b2,
            G1Point c1, G2Point c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point a1, G2Point a2,
            G1Point b1, G2Point b2,
            G1Point c1, G2Point c2,
            G1Point d1, G2Point d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
    
    
contract Groth16 {
    using Pairing for *;
    
    struct VerifyingKey {
        Pairing.G1Point alpha_g1;
        Pairing.G1Point beta_g1;
        Pairing.G2Point beta_g2;
        Pairing.G2Point gamma_g2;
        Pairing.G1Point delta_g1;
        Pairing.G2Point delta_g2;
        Pairing.G1Point[] IC;
    }
    
    //     pub a: E::G1Affine,
    // pub b: E::G2Affine,
    // pub c: E::G1Affine
    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }
    
    struct Pair {
        Pairing.G1Point a;
        Pairing.G2Point b;
    }
    
    struct PreparedVerifyingKey {
        /// Pair for pairing result of alpha*beta
        Pair alpha_g1_beta_g2;
        /// -gamma in G2
        Pairing.G2Point neg_gamma_g2;
        /// -delta in G2
        Pairing.G2Point neg_delta_g2;
        /// accumulated public inputs
        Pairing.G1Point ic;
    }
    
    function verifyingKey() pure internal returns (VerifyingKey vk) {
        vk.alpha_g1 = Pairing.G1Point(0x23b16b75c253c67a07b2dfb4642f916ce483f52d7d957c43f1cafa9e8efbd4b6, 0x10b9cf66c4b02c8eedc287dbfabde1d7e1be9c817eced0610e4232063b473347);
        // vk.beta_g1 = Pairing.G1Point(0x23b16b75c253c67a07b2dfb4642f916ce483f52d7d957c43f1cafa9e8efbd4b6, 0x10b9cf66c4b02c8eedc287dbfabde1d7e1be9c817eced0610e4232063b473347);
        vk.beta_g2 = Pairing.G2Point([0x8d841a59c62049761286964354fbb9547aacb249038adcb0b8b393a0a71f872, 0x23bd90ef5307660e965fd3144418d2b5a8e6c22a87900541e12745ea62f6375f], [0x10935f302a61d826b52731e5951219552832fe1be64ef191364fb8a264036d67, 0x608317e583295bdc60d86315f7923e2677143c6eeb381f8f4b828bf1a055fcd]);
        vk.gamma_g2 = Pairing.G2Point([0x723f2cb7ff1065bbb44c112f68e1b632de6b6be20920beae4f28d9e0057cc47, 0xdd6e0ed155dbbc30988ad7bfd9cbcab76850d09bb6b668c1b831354fe2c1180], [0x2fbb278596ffa9342d987295ada995129d5ed9b484a3337cbd095b38f1a834bd, 0x19bb949e51477e54f9ae892093beda448c33b21b43366502cd4d8a02897017a]);
        // vk.delta_g1 = Pairing.G1Point(0x22dc5c5252437b5f3feb464de52cb4306a0b45bbad6a4a19b36b1f991eabbe47, 0x177a001e3312096da4d75bfb2b4cc07bec195dccb48ecc6808f81c5f232e02e);
        vk.delta_g2 = Pairing.G2Point([0x723f2cb7ff1065bbb44c112f68e1b632de6b6be20920beae4f28d9e0057cc47, 0xdd6e0ed155dbbc30988ad7bfd9cbcab76850d09bb6b668c1b831354fe2c1180], [0x2fbb278596ffa9342d987295ada995129d5ed9b484a3337cbd095b38f1a834bd, 0x19bb949e51477e54f9ae892093beda448c33b21b43366502cd4d8a02897017a]);
        vk.IC = new Pairing.G1Point[](7);
        vk.IC[0] = Pairing.G1Point(0x406d95f7ae8feb816b5a4b4cf4a949730f31de0b3ff1e8b800db9969514a256, 0xe0818f24fef31a82b9e7e587c9934f812e5a196a5e7aa7d495a8494f9557f4c);
        vk.IC[1] = Pairing.G1Point(0xf394dc0e39f79bee4a1e0577299de796c7a03ad6e3949884d2d2fbd73f0d76c, 0x16a514b14810b2217478d803fb68372e34dde4fb624b9f4e156470364cb19402);
        vk.IC[2] = Pairing.G1Point(0x134d26c1eec281bedabb8d4ee3fb61d2e9113668b3fa45f110d8547fd8f5b94d, 0x59f3d50872f8ee5662e25fc1f13e08acc01f5a7ac049b3661b87cd2b78bdd11);
        vk.IC[3] = Pairing.G1Point(0xcd6823439d212cdf695ae58c3a9cb50bc31f285e986a1ca00aed91669401419, 0xbea35dbd15dd6e212050e923a6f748a981ea0f1bca31305e87a487c5c07f506);
        vk.IC[4] = Pairing.G1Point(0x139af07e752cc39bc1a2c6b0468415afa072bddd5599f38e7cc4031031a5ec02, 0x27233e6a491cbdb09fd5b3b94917658ab20b2207f3d7e6aa556ca68bff5af037);
        vk.IC[5] = Pairing.G1Point(0x20a7eda84420d312d03674aff46ae1202db426e9ae4ea1d400e385973ea31497, 0x61e54c3741544a6a99149a282cf1c9c08e1dd6061a593260bebba7d5c5e0b55);
        vk.IC[6] = Pairing.G1Point(0x8ed7634c368516b852917dac2d165ac153204b550c5ba0456512066daef108b, 0x14c048afac3cdb256d375825101691093f73aeaf6802df2fba3c0e83de9feb86);
    }
    
    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // A * B - inputs * gamma - C * delta = alpha * beta
    // or equivalently:
    // A * B + inputs * (-gamma) + C * (-delta) = alpha * beta
    // which allows us to do a single final exponentiation.
    
    function verify(uint[] input, Proof proof) internal view returns (uint) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
            
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        bool valid = Pairing.pairingProd4(proof.A, proof.B,
                                            vk_x.negate(), vk.gamma_g2,
                                            proof.C.negate(), vk.delta_g2,
                                            vk.alpha_g1.negate(), vk.beta_g2);
        if (valid) {
            return 0;
        }
        return 1;
        // Pair memory pair = Pair(vk.alpha_g1, vk.beta_g2);
        // PreparedVerifyingKey memory preparedKey;
        // preparedKey.alpha_g1_beta_g2 = pair;
        // preparedKey.neg_gamma_g2 = vk.gamma_g2.negate();
        // preparedKey.neg_delta_g2 = vk.delta_g2.negate();
        // preparedKey.ic = vk_x;
        // return verify(preparedKey, proof);
    }
        
    // function verifyInt(PreparedVerifyingKey vk, Proof proof) internal pure returns (uint) {
        // return 0;
        // if (!Pairing.pairingProd2(proof.A, vk.A, Pairing.negate(proof.A_p), Pairing.P2())) return 1;
        // if (!Pairing.pairingProd2(vk.B, proof.B, Pairing.negate(proof.B_p), Pairing.P2())) return 2;
        // if (!Pairing.pairingProd2(proof.C, vk.C, Pairing.negate(proof.C_p), Pairing.P2())) return 3;
        // if (!Pairing.pairingProd3(
        //     proof.K, vk.gamma,
        //     Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.A, proof.C))), vk.gammaBeta2,
        //     Pairing.negate(vk.gammaBeta1), proof.B
        // )) return 4;
        // if (!Pairing.pairingProd3(
        //         Pairing.addition(vk_x, proof.A), proof.B,
        //         Pairing.negate(proof.H), vk.Z,
        //         Pairing.negate(proof.C), Pairing.P2()
        // )) return 5;
        // return 0;
    // }
    
    function veryfyProof(uint256[18] zkSnarkProof, uint256[7] publicInputs) public view {
        Proof memory proof;
        proof.A = Pairing.G1Point(zkSnarkProof[0], zkSnarkProof[1]);
        proof.B = Pairing.G2Point([zkSnarkProof[2], zkSnarkProof[3]], [zkSnarkProof[4], zkSnarkProof[5]]);
        proof.C = Pairing.G1Point(zkSnarkProof[6], zkSnarkProof[7]);
        uint[] memory inputValues = new uint[](publicInputs.length);
        for(uint i = 0; i < publicInputs.length; i++){
            inputValues[i] = publicInputs[i];
        }

        uint isValidMove = verify(inputValues, proof);
        if (isValidMove != 0) {
            return;
        }
        revert("Proof is invalid");
    }
}