import { expect } from "chai";
import * as chai from "chai";
import chaiAsPromised from "chai-as-promised";
import { describe, it } from "mocha";
// @ts-ignore
import * as circom_tester from "circom_tester";
// @ts-ignore
import * as ff from "ffjavascript";
chai.use(chaiAsPromised);
const CIRCUIT_PATH = "./test/test_elgamal_encrypt.circom";
function toCircomInput(obj) {
    if (typeof obj === "bigint") {
        return obj.toString();
    }
    else if (Array.isArray(obj)) {
        return obj.map(toCircomInput);
    }
    else if (typeof obj === "object" && obj !== null) {
        const res = {};
        for (const key of Object.keys(obj)) {
            res[key] = toCircomInput(obj[key]);
        }
        return res;
    }
    else {
        return obj;
    }
}
describe("ElGamal Encrypt Circuit", function () {
    this.timeout(100000);
    let babyjub;
    let F;
    let scalar;
    const BASE_POINT = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553n,
        16950150798460657717958625567821834550301663161624707787222815936182638968203n
    ];
    function generateRandomScalar(numBits) {
        const threshold = scalar.exp(scalar.e(2), scalar.e(numBits));
        let sk;
        do {
            const randomFieldElement = babyjub.F.random();
            sk = scalar.fromRprLE(randomFieldElement);
        } while (scalar.geq(sk, threshold));
        return sk;
    }
    before(async () => {
        // @ts-ignore
        const circomlibjs = await import("circomlibjs");
        babyjub = await circomlibjs.buildBabyjub();
        scalar = ff.Scalar;
        F = babyjub.F;
    });
    it("should encrypt a point correctly", async () => {
        const circuit = await circom_tester.wasm(CIRCUIT_PATH);
        // Generate test data
        const sk = generateRandomScalar(251);
        const pk = babyjub.mulPointEscalar(babyjub.Base8, sk);
        const r = generateRandomScalar(251);
        const ic0 = [F.random(), F.random()];
        const ic1 = [F.random(), F.random()];
        // --- ElGamal encryption --- //
        const rG = babyjub.mulPointEscalar(babyjub.Base8, r);
        const rPK = babyjub.mulPointEscalar(pk, r);
        const expectedC0 = babyjub.addPoint(rG, ic0);
        const expectedC1 = babyjub.addPoint(rPK, ic1);
        // Prepare circuit inputs
        const input = {
            ic0: ic0.map(x => babyjub.F.toObject(x)),
            ic1: ic1.map(x => babyjub.F.toObject(x)),
            r: BigInt(r),
            pk: pk.map((x) => babyjub.F.toObject(x))
        };
        // Calculate witness
        const witness = await circuit.calculateWitness(input, true);
        // Fetch outputs
        const c0x = witness[1];
        const c0y = witness[2];
        const c1x = witness[3];
        const c1y = witness[4];
        // Validate that circuit outputs match manual computation
        expect(c0x.toString()).to.equal(babyjub.F.toObject(expectedC0[0]).toString());
        expect(c0y.toString()).to.equal(babyjub.F.toObject(expectedC0[1]).toString());
        expect(c1x.toString()).to.equal(babyjub.F.toObject(expectedC1[0]).toString());
        expect(c1y.toString()).to.equal(babyjub.F.toObject(expectedC1[1]).toString());
    });
    it("should fail for an invalid point", async () => {
        const circuit = await circom_tester.wasm(CIRCUIT_PATH);
        const invalidPk = {
            x: "1234567890123456789012345678901234567890",
            y: "9876543210987654321098765432109876543210"
        };
        const r = generateRandomScalar(251);
        const ic0 = [F.random(), F.random()];
        const ic1 = [F.random(), F.random()];
        const input = {
            ic0: ic0.map(x => babyjub.F.toObject(x)),
            ic1: ic1.map(x => babyjub.F.toObject(x)),
            r: BigInt(r),
            pk: invalidPk
        };
        await expect(circuit.calculateWitness(input, true)).to.be.rejectedWith(Error, /Not enough values/);
    });
});
