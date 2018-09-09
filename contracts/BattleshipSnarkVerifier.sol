// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
    /// @return the sum of two points of G1
    function addition(G1Point p1, G1Point p2) internal returns (G1Point r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 6, 0, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }
    /// @return the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point p, uint s) internal returns (G1Point r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 7, 0, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] p1, G2Point[] p2) internal returns (bool) {
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
            success := call(sub(gas, 2000), 8, 0, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point a1, G2Point a2, G1Point b1, G2Point b2) internal returns (bool) {
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
    ) internal returns (bool) {
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
    ) internal returns (bool) {
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
library Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G2Point A;
        Pairing.G1Point B;
        Pairing.G2Point C;
        Pairing.G2Point gamma;
        Pairing.G1Point gammaBeta1;
        Pairing.G2Point gammaBeta2;
        Pairing.G2Point Z;
        Pairing.G1Point[] IC;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G1Point A_p;
        Pairing.G2Point B;
        Pairing.G1Point B_p;
        Pairing.G1Point C;
        Pairing.G1Point C_p;
        Pairing.G1Point K;
        Pairing.G1Point H;
    }
    function verifyingKey() pure internal returns (VerifyingKey vk) {
        vk.A = Pairing.G2Point([0x95aacb3c23ba931cea76b29a19617c347943ecf1002fc0fcf798e0f8d74846c, 0x6d039a9508f5e58dd3646aec40b650cf2622990ef101628046382d9d0a11c2b], [0x1396a7eda2554a0ddef4978de4de39b8618c0d170eaa3b4e3528c1e5e44c7050, 0x35186be372d0ef1ca7821d2eeb6575accda23f59fe655f4d087031b75ca9d48]);
        vk.B = Pairing.G1Point(0x23b16b75c253c67a07b2dfb4642f916ce483f52d7d957c43f1cafa9e8efbd4b6, 0x10b9cf66c4b02c8eedc287dbfabde1d7e1be9c817eced0610e4232063b473347);
        vk.C = Pairing.G2Point([0x8d841a59c62049761286964354fbb9547aacb249038adcb0b8b393a0a71f872, 0x23bd90ef5307660e965fd3144418d2b5a8e6c22a87900541e12745ea62f6375f], [0x10935f302a61d826b52731e5951219552832fe1be64ef191364fb8a264036d67, 0x608317e583295bdc60d86315f7923e2677143c6eeb381f8f4b828bf1a055fcd]);
        vk.gamma = Pairing.G2Point([0x838d4dcd872e6bcc73ef8d9f2d61c1b1223672a4ce4483d14aea08acc895106, 0xc700c249203de561efcda3fd4ec7658d528701da3c1fca098a2d42f011fde37], [0x2979bf58a5a9ef40265dea31187fd807257683846c5832c7b87951a78aa68841, 0x19e61fbd9e5b5e25dd7d110cd4b0071123975620e37c3cd72a101b63eff4f185]);
        vk.gammaBeta1 = Pairing.G1Point(0x22dc5c5252437b5f3feb464de52cb4306a0b45bbad6a4a19b36b1f991eabbe47, 0x177a001e3312096da4d75bfb2b4cc07bec195dccb48ecc6808f81c5f232e02e);
        vk.gammaBeta2 = Pairing.G2Point([0x723f2cb7ff1065bbb44c112f68e1b632de6b6be20920beae4f28d9e0057cc47, 0xdd6e0ed155dbbc30988ad7bfd9cbcab76850d09bb6b668c1b831354fe2c1180], [0x2fbb278596ffa9342d987295ada995129d5ed9b484a3337cbd095b38f1a834bd, 0x19bb949e51477e54f9ae892093beda448c33b21b43366502cd4d8a02897017a]);
        vk.Z = Pairing.G2Point([0x15425ab686d62e846de5ca98c92843cad80f06401610fcce27cf6f94e07f7f8b, 0xe21bc3f9c196bb742aa2404a6550635fd632b86cb0fbae13962df909543c7c3], [0x6538ba629c4809a327453895dade6110275faa25e14e4ce6390c3b095f6519c, 0x5aaf52260e7758c6cd487c1e88ef9791b518fbf09e0ec5402825687b75f3ab9]);
        vk.IC = new Pairing.G1Point[](7);
        vk.IC[0] = Pairing.G1Point(0x406d95f7ae8feb816b5a4b4cf4a949730f31de0b3ff1e8b800db9969514a256, 0xe0818f24fef31a82b9e7e587c9934f812e5a196a5e7aa7d495a8494f9557f4c);
        vk.IC[1] = Pairing.G1Point(0xf394dc0e39f79bee4a1e0577299de796c7a03ad6e3949884d2d2fbd73f0d76c, 0x16a514b14810b2217478d803fb68372e34dde4fb624b9f4e156470364cb19402);
        vk.IC[2] = Pairing.G1Point(0x134d26c1eec281bedabb8d4ee3fb61d2e9113668b3fa45f110d8547fd8f5b94d, 0x59f3d50872f8ee5662e25fc1f13e08acc01f5a7ac049b3661b87cd2b78bdd11);
        vk.IC[3] = Pairing.G1Point(0xcd6823439d212cdf695ae58c3a9cb50bc31f285e986a1ca00aed91669401419, 0xbea35dbd15dd6e212050e923a6f748a981ea0f1bca31305e87a487c5c07f506);
        vk.IC[4] = Pairing.G1Point(0x139af07e752cc39bc1a2c6b0468415afa072bddd5599f38e7cc4031031a5ec02, 0x27233e6a491cbdb09fd5b3b94917658ab20b2207f3d7e6aa556ca68bff5af037);
        vk.IC[5] = Pairing.G1Point(0x20a7eda84420d312d03674aff46ae1202db426e9ae4ea1d400e385973ea31497, 0x61e54c3741544a6a99149a282cf1c9c08e1dd6061a593260bebba7d5c5e0b55);
        vk.IC[6] = Pairing.G1Point(0x8ed7634c368516b852917dac2d165ac153204b550c5ba0456512066daef108b, 0x14c048afac3cdb256d375825101691093f73aeaf6802df2fba3c0e83de9feb86);
    }
    function verify(uint[] input, Proof proof) internal returns (uint) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd2(proof.A, vk.A, Pairing.negate(proof.A_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.B, proof.B, Pairing.negate(proof.B_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.C, vk.C, Pairing.negate(proof.C_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.K, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.A, proof.C))), vk.gammaBeta2,
            Pairing.negate(vk.gammaBeta1), proof.B
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.A), proof.B,
                Pairing.negate(proof.H), vk.Z,
                Pairing.negate(proof.C), Pairing.P2()
        )) return 5;
        return 0;
    }
}
