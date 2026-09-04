#include <iostream>
#include "CKKSController.h"
#include "chrono"
#include <functional>
#include "Utils.h"

using namespace std;
using namespace chrono;

CKKSController cc;
int ring_size = 12;
int verbose = 1;
int wordsize = 64;

int startinglevel = 12;

bool test = false;
bool input_mode = false;
bool mev = false;
bool ascon = false;
bool noise_estimate = false;

void read_arguments(int argc, char *argv[]);
void random_operations_batched(int bits);

void experiment_division(int bits);
void experiment_squareroot(int bits);
void experiment_hash_ascon();
void experiment_mev();
void experiment_noise_estimate();
void precompute_stuff();

vector<double> coeffsSinc;
std::shared_ptr<void> precomp4bits;

int main(int argc, char *argv[])
{
    read_arguments(argc, argv);

    // Con 13 levels 256-bits
    cc.generate_context_for_bootstrapping(1 << ring_size, 16);

    cc.generate_rotations_for_additions(wordsize * 2);
    cc.generate_rotations_for_multiplications(wordsize);
    cc.generate_rotations_for_bit_length(wordsize);

    if (ascon)
    {
        cc.generate_rotation_key(64 * 64 / 2);
        cc.generate_rotation_key(5 * 64 * 64 / 2);
        cc.generate_rotation_key(4 * 64 * 64 / 2);
        cc.generate_rotation_key((cc.get_context()->GetRingDimension() / (64 * 64) - 5) * 64 * 64 / 2);
        cc.generate_rotation_keys({19, 28, 61, 39, 1, 6, 10, 17, 7, 41});
    }

    cc.get_context()->LoadContext(cc.publicKey);

    if (!ascon)
    {
        Ctxt a = cc.encrypt(cc.encode(0, startinglevel));
        int zslots = cc.get_context()->GetRingDimension() / (wordsize * wordsize);
        cc.get_context()->ProcessArrayPrecomputations(a, wordsize, 1 << (ring_size - 1), 1);
        // cc.get_context()->IntegerMultPrecomputations(a, wordsize, zslots, 1 << (ring_size - 1), 1);
        precompute_stuff();
    }

    if (mev)
    {
        experiment_mev();
        exit(0);
    }

    if (ascon)
    {
        experiment_hash_ascon();
        exit(0);
    }

    if (noise_estimate)
    {
        experiment_noise_estimate();
        exit(0);
    }
    /*
     * Experiments
     */
    // experiment_hash_ascon();
    // experiment_division(wordsize);
    // experiment_mev();

    /*
     * End experiments
     */

    if (test)
    {
        cout << "Keygen works, you are good to go to use the program :)" << endl;
        return 0;
    }

    for (int i = 0; i < 1; i++)
        random_operations_batched(wordsize);
}

void experiment_hash_ascon()
{
    std::cout << "ASCON!" << std::endl;
    int bits = 64;

    int a = 12;
    int b = 12;
    uint64_t rate = 8;
    int taglen = 256;

    /*
     * Offline part
     */

    uint64_t iv[40] = {2, 0, (uint8_t)((b << 4) + a), (uint8_t)(taglen & 0xFF), (uint8_t)(taglen >> 8), rate, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    uint64_t S[5];
    for (int w = 0; w < 5; w++)
    {
        S[w] = 0;
        for (int i = 0; i < 8; i++)
            S[w] |= (uint64_t)iv[8 * w + i] << (i * 8);
    }

    ascon_permutation(S, 12);

    vector<uint128_t> S_vector;
    S_vector.push_back(S[0]);
    S_vector.push_back(S[1]);
    S_vector.push_back(S[2]);
    S_vector.push_back(S[3]);
    S_vector.push_back(S[4]);
    S_vector.push_back(0);
    S_vector.push_back(0);
    S_vector.push_back(0);

    Ctxt Sctxt = cc.encrypt_multi_int(S_vector, bits, startinglevel);

    /*
     * Online phase
     */

    std::string message = "67";
    int msg_len = message.size();

    // m_padding
    std::vector<uint8_t> m_padding(rate - (msg_len % rate), 0x00);
    m_padding[0] = 0x01;

    // m_padded
    std::vector<uint8_t> m_padded(message.begin(), message.end());
    m_padded.insert(m_padded.end(), m_padding.begin(), m_padding.end());

    // bytes_to_int (little-endian)
    uint64_t m_int = 0;
    for (uint32_t i = 0; i < m_padded.size(); i++)
        m_int |= (uint64_t)m_padded[i] << (i * 8);

    cout << m_int << endl;

    /*
     * Assuming m_int to occupy 8 bytes
     */

    /*
     * CLEAR VERSION
     */
    S[0] ^= m_int;
    ascon_permutation(S, 12);

    /*
     * FHE VERSION
     */
    cout << "Let's go with FHE" << endl;

    vector<uint128_t> M_vector;
    M_vector.push_back(m_int);

    for (uint32_t i = 0; i < cc.get_context()->GetRingDimension() / (bits * bits) - 1; i++)
        M_vector.push_back(0);

    Ctxt Mctxt = cc.encrypt_multi_int(M_vector, bits, startinglevel);

    // XOR
    Sctxt = cc.square(cc.sub(Sctxt, Mctxt));

    // Sctxt = cc.binboot(Sctxt);

    cc.ascon_permutation(Sctxt, cc.get_context()->GetRingDimension() / (bits * bits));

    cout << "Obtained : " << cc.print_ints(Sctxt, bits, 5) << endl;
    cout << "Expected : " << S[0] << ",  " << S[1] << ", " << S[2] << ", " << S[3] << ", " << S[4] << endl;
}

void experiment_mev()
{
    int bits = 128;

    vector<uint128_t> X;
    X.push_back(15187039806);

    vector<uint128_t> Y;
    Y.push_back(11870329);

    vector<uint128_t> ext_price;
    ext_price.push_back(1284000);

    vector<uint128_t> g;
    g.push_back(997);

    for (uint32_t i = 0; i < cc.get_context()->GetRingDimension() / (bits * bits) - 1; i++)
    {
        // Filling the rest of slots with zeroes
        X.push_back(0);
        Y.push_back(0);
        ext_price.push_back(0);
        g.push_back(0);
    }

    Ctxt X_ciph = cc.encrypt_multi_int(X, bits, 11);
    Ctxt Y_ciph = cc.encrypt_multi_int(Y, bits, 11);
    Ctxt ext_price_ciph = cc.encrypt_multi_int(ext_price, bits, 11);
    Ctxt g_ciph = cc.encrypt_multi_int(g, bits, 11);

    cout << "X: " << cc.print_ints(X_ciph, bits, 1) << endl
         << "Y: " << cc.print_ints(Y_ciph, bits, 1) << endl
         << "ext_price: " << cc.print_ints(ext_price_ciph, bits, 1) << endl
         << "g: " << cc.print_ints(g_ciph, bits, 1) << endl;

    Ctxt term1 = cc.mul_integer(X_ciph, Y_ciph, bits, bits, 1, 1, false);
    Ctxt term2 = cc.mul_integer(ext_price_ciph, g_ciph, bits, bits, 1, 1, false);

    cout << "[X * Y]: " << cc.print_ints(term1, bits, 1) << ", [ext * g]: " << cc.print_ints(term2, bits, 1) << endl;

    Ctxt total = cc.mul_integer(term1, term2, bits, bits, 1, 1, false);

    cout << "[X * Y * ext * g]: " << cc.print_ints(total, bits, 1) << endl;
    cout << "Now the long one: computing the square root" << endl;

    Ctxt squareroot = cc.square_root_integer(total, bits, 1);

    cout << "[sqrt(X * Y * ext * g)]: " << cc.print_ints(squareroot, bits, 1) << endl;

    squareroot = cc.binboot(cc.sub_integer(squareroot, X_ciph, bits));

    cout << "[sqrt(X * Y * ext * g) - X]: " << cc.print_ints(squareroot, bits, 1) << endl;

    Ctxt result = cc.div_integer(squareroot, 997, bits, 1);

    cout << "[(sqrt(X * Y * g * ext) - X) / g]: " << cc.print_ints(result, bits, 1) << endl;
}

void experiment_squareroot(int bits)
{
    vector<uint128_t> a;

    a.push_back(random_number(bits));

    for (uint32_t i = 0; i < cc.get_context()->GetRingDimension() / (bits * bits) - 1; i++)
    {
        a.push_back(random_number(bits));
    }

    cout << "Numbers:   " << to_string_uint128(a) << endl;

    Ctxt c = cc.encrypt_multi_int(a, bits, 11);

    int zslots = cc.get_context()->GetRingDimension() / (bits * bits);

    Ctxt result = cc.square_root_integer(c, bits, zslots);

    cout << "Obtained: " << cc.print_ints(result, bits, zslots) << endl;
    cout << "Expected: " << to_string_uint128(sqrt_simd(a)) << endl;

    exit(0);
}

void experiment_division(int bits)
{
    vector<uint128_t> a;
    vector<uint128_t> b;

    a.push_back(random_number(bits));
    b.push_back(random_number(bits / 2));

    cout << "Numerator:   " << to_string_uint128(a[0]) << endl;
    cout << "Denominator: " << to_string_uint128(b[0]) << endl;

    for (uint32_t i = 0; i < cc.get_context()->GetRingDimension() / (bits * bits) - 1; i++)
    {
        a.push_back(random_number(bits));
        b.push_back(random_number(bits / 2));
    }

    Ctxt numerator = cc.encrypt_multi_int(a, bits, startinglevel);
    Ctxt denominator = cc.encrypt_multi_int(b, bits, startinglevel);

    int zslots = cc.get_context()->GetRingDimension() / (bits * bits);

    Ctxt result = cc.div_integer(numerator, denominator, bits, zslots);

    cout << "Expected: " << to_string_uint128(div_simd(a, b)) << endl;
    cout << "Obtained: " << cc.print_ints(result, bits, zslots, false) << endl;

    exit(0);
}

void experiment_noise_estimate()
{
    vector<uint128_t> a;

    int bits = wordsize;

    for (uint32_t i = 0; i < cc.get_context()->GetRingDimension() / (bits * bits); i++)
    {
        a.push_back(0);
    }

    Ctxt c = cc.encrypt_multi_int(a, bits, 11);

    int zslots = cc.get_context()->GetRingDimension() / (bits * bits);

    Ctxt result = cc.binboot(cc.add_integer(c, c, bits, zslots));

    vector<double> result_vector = cc.decode(cc.decrypt(result));
    for (double &i : result_vector)
    {
        i = abs(i);
    }

    double average = accumulate(result_vector.begin(), result_vector.end(), 0.0) / result_vector.size();

    average = -log2(average);                                                         // Error to precision bits
    double minimum = -log2(*max_element(result_vector.begin(), result_vector.end())); // We invert minimum and maximum as max error => min precision
    double maximum = -log2(*min_element(result_vector.begin(), result_vector.end()));

    cout << "Precision bits in addition (" << bits << " bits)" << endl;
    cout << "Average : " << average << endl;
    cout << "Minimum : " << minimum << endl;
    cout << "Maximum : " << maximum << endl
         << "*****" << endl;

    result = cc.eq_integer(c, c, bits, zslots);

    result_vector = cc.decode(cc.decrypt(result));

    // Slots in (relative) position 0 are equal to 1, let's correct them
    for (uint32_t i = 0; i < zslots; i++)
        result_vector[i * (bits * bits) / 2] -= 1;

    for (double &i : result_vector)
    {
        i = abs(i);
    }

    average = accumulate(result_vector.begin(), result_vector.end(), 0.0) / result_vector.size();

    average = -log2(average);                                                  // Error to precision bits
    minimum = -log2(*max_element(result_vector.begin(), result_vector.end())); // We invert minimum and maximum as max error => min precision
    maximum = -log2(*min_element(result_vector.begin(), result_vector.end()));

    cout << "Precision bits in equality (" << bits << " bits)" << endl;
    cout << "Average : " << average << endl;
    cout << "Minimum : " << minimum << endl;
    cout << "Maximum: " << maximum << endl
         << "*****" << endl;

    result = cc.mul_integer(c, c, bits, bits, zslots, zslots, true);

    result_vector = cc.decode(cc.decrypt(result));
    for (double &i : result_vector)
    {
        i = abs(i);
    }

    average = accumulate(result_vector.begin(), result_vector.end(), 0.0) / result_vector.size();

    average = -log2(average);                                                  // Error to precision bits
    minimum = -log2(*max_element(result_vector.begin(), result_vector.end())); // We invert minimum and maximum as max error => min precision
    maximum = -log2(*min_element(result_vector.begin(), result_vector.end()));

    cout << "Precision bits in multiplication (" << bits << " bits)" << endl;
    cout << "Average : " << average << endl;
    cout << "Minimum : " << minimum << endl;
    cout << "Maximum: " << maximum << endl
         << "*****" << endl;

    result = cc.square_root_integer(c, bits, zslots);

    result_vector = cc.decode(cc.decrypt(result));
    for (double &i : result_vector)
    {
        i = abs(i);
    }

    average = accumulate(result_vector.begin(), result_vector.end(), 0.0) / result_vector.size();

    average = -log2(average);                                                  // Error to precision bits
    minimum = -log2(*max_element(result_vector.begin(), result_vector.end())); // We invert minimum and maximum as max error => min precision
    maximum = -log2(*min_element(result_vector.begin(), result_vector.end()));

    cout << "Precision bits in square root (" << bits << " bits)" << endl;
    cout << "Average : " << average << endl;
    cout << "Minimum : " << minimum << endl;
    cout << "Maximum : " << maximum << endl
         << "*****" << endl;

    result = cc.div_integer(c, c, bits, zslots);

    result_vector = cc.decode(cc.decrypt(result));
    for (double &i : result_vector)
    {
        i = abs(i);
    }

    average = accumulate(result_vector.begin(), result_vector.end(), 0.0) / result_vector.size();

    average = -log2(average);                                                  // Error to precision bits
    minimum = -log2(*max_element(result_vector.begin(), result_vector.end())); // We invert minimum and maximum as max error => min precision
    maximum = -log2(*min_element(result_vector.begin(), result_vector.end()));

    cout << "Precision bits in division (" << bits << " bits)" << endl;
    cout << "Average : " << average << endl;
    cout << "Minimum : " << minimum << endl;
    cout << "Maximum : " << maximum << endl
         << "*****" << endl;

    exit(0);
}

void random_operations_batched(int bits)
{
    int reps = 6;

    int slots = cc.get_context()->GetRingDimension() / (bits * bits);

    vector<uint128_t> a;
    vector<uint128_t> b;

    std::cout << endl
              << "Running batched " << bits << "-bits operations experiment!" << endl;

    for (int i = 0; i < slots; i++)
    {
        a.push_back(random_number(bits));
        b.push_back(random_number(bits / 2));
    }

    // a = { 201, 240, 254, 139, 152, 215, 32, 210, 182, 152, 174, 225, 150, 79, 76, 163, 78, 15, 209, 20, 71, 200, 103, 102, 130, 22, 144, 123, 78, 81, 2, 226, 159, 138, 187, 18, 141, 69, 141, 101, 213, 218, 128, 187, 55, 71, 218, 62, 190, 170, 215, 178, 215, 191, 191, 239, 226, 42, 10, 202, 159, 240, 20, 160 };
    // b = { 74, 223, 20, 41, 0, 219, 204, 159, 252, 195, 127, 187, 129, 17, 28, 17, 59, 166, 112, 152, 200, 160, 126, 121, 115, 158, 19, 64, 133, 240, 132, 111, 75, 234, 124, 183, 27, 1, 206, 35, 74, 0, 122, 52, 131, 40, 150, 92, 140, 141, 9, 192, 157, 64, 179, 202, 208, 17, 184, 86, 145, 64, 143, 19 };

    // a = {15156, 28708, 41704, 46469, 30961, 48084, 34112, 33859, 43114, 22259, 46172, 11048, 22707, 37764, 38525, 33850};
    // b = {63871, 63045, 46605, 19526, 7301, 26500, 37975, 13923, 39433, 1130, 52586, 54314, 29762, 32718, 64035, 25465};

    // a = {16100571885011951808ULL};
    // b = {18275348781532081914ULL};

    if (verbose >= 2)
    {
        std::cout << "a: " << to_string_uint128(a) << endl
                  << "b: " << to_string_uint128(b) << endl
                  << endl;
    }

    Ctxt c1 = cc.encrypt_multi_int(a, bits, startinglevel);
    Ctxt c2 = cc.encrypt_multi_int(b, bits, startinglevel);

    auto time = steady_clock::now();

    {
        // Ctxt csum = cc.binboot(cc.add_integer(c1, c2, bits));
        Ctxt cand = cc.binboot(cc.mult(c1, c2));

        for (int i = 0; i < reps - 1; i++)
        {
            cc.binboot(
               cc.mult(c1, c2));
        }

        std::cout << "Logical AND (a * b)" << endl;
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " AND took on average: ", reps);


        std::cout << "-----" << endl;
    }

    time = steady_clock::now();

    {
        Ctxt cor = cc.binboot(cc.get_context()->EvalBinaryOR(c1, c2));

        for (int i = 0; i < reps - 1; i++)
        {
            cc.binboot(
               cc.get_context()->EvalBinaryOR(c1, c2));
        }

        std::cout << "Logical OR ((a + b) - (a * b))" << endl;
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " OR took on average: ", reps);


        std::cout << "-----" << endl;
    }

    time = steady_clock::now();

    {
        // Ctxt csum = cc.binboot(cc.add_integer(c1, c2, bits));
        Ctxt csum = cc.binboot(cc.get_context()->EvalAddInteger(c1, c2, bits));

        for (int i = 0; i < reps - 1; i++)
        {
            cc.binboot(
                cc.get_context()->EvalAddInteger(c1, c2, bits));
        }

        std::cout << "Addition (a + b)" << endl;
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " additions took on average: ", reps);

        if (verbose >= 2)
        {
            std::cout << "Expected: " << to_string_uint128(add_simd(a, b)) << endl;
            std::cout << "Obtained: " << cc.print_ints(csum, bits + 1, slots);
            std::cout << endl;
        }

        std::cout << "-----" << endl;
    }

    time = steady_clock::now();

    {
        Ctxt ceq = cc.get_context()->EvalEqualInteger(c1, c2, bits, slots, coeffsSinc, cc.depth);

        for (int i = 0; i < reps - 1; i++)
        {
            cc.get_context()->EvalEqualInteger(c1, c2, bits, slots, coeffsSinc, cc.depth);
        }

        std::cout << "Equality (a = b)" << endl;
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " equalities took on average: ", reps);
        if (verbose >= 2)
        {
            std::cout << "Expected: ";
            print_vector(eq_simd(a, b));
            std::cout << endl;
            std::cout << "Obtained: ";
            print_vector(first_bits(cc.decode(cc.decrypt(ceq)), slots, bits));
            std::cout << endl;
        }

        std::cout << "-----" << endl;
    }

    time = steady_clock::now();

    {
        for (int i = 0; i < reps - 1; i++)
            cc.get_context()->EvalMultInteger(c1, c2, bits, slots, false);

        Ctxt cmultmod = cc.get_context()->EvalMultInteger(c1, c2, bits, slots, false);

        std::cout << "Multiplication (a * b) % 2^n" << endl;
        if (verbose >= 2)
        {
            std::cout << "Expected: " << to_string_uint128(mul_simd(a, b, bits)) << endl;
            std::cout << "Obtained: " << cc.print_ints(cmultmod, bits, slots);
            std::cout << endl;
        }
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " multiplications took on average: ", reps);
        std::cout << "-----" << endl;
    }

    time = steady_clock::now();

    {
        Ctxt cmult = cc.get_context()->EvalMultInteger(c1, c2, bits, slots, true);
        for (int i = 0; i < reps - 1; i++)
        {
            cc.get_context()->EvalMultInteger(c1, c2, bits, slots, true);
        }

        if (bits > 64)
        {
            std::cout << "Multiplication with overflow (a * b), Warning: results will be inaccurate as we only have access to uint128_t :-(" << endl;
        }
        else
        {
            std::cout << "Multiplication with overflow (a * b)" << endl;
        }

        if (verbose >= 2)
        {
            std::cout << "Expected: " << to_string_uint128(mul_simd(a, b, 2 * bits)) << endl;
            std::cout << "Obtained: " << cc.print_ints(cmult, bits, slots, true);
            std::cout << endl;
        }

        if (verbose >= 1)
            print_duration(time, to_string(reps) + " multiplications took on average: ", reps);
    }

    std::cout << "-----" << endl;

    {
        time = steady_clock::now();

        Ctxt cshift = cc.rot(c1, -2);
        for (int i = 0; i < reps - 1; i++)
        {
            cc.rot(c1, -2);
        }
        std::cout << "Logical shift (a * b << 2)" << endl;
        if (verbose >= 2)
        {
            std::cout << "Expected: " << to_string_uint128(shift_simd(a, 2)) << endl;
            std::cout << "Obtained: " << cc.print_ints(cshift, bits + 2, slots);
            std::cout << endl;
        }
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " shifts took on average: ", reps);
        std::cout << "-----" << endl;
    }

    time = steady_clock::now();

    // Ctxt cdiv = cc.div_integer(c1, c2, bits, slots);

    {
        Ctxt cdiv = cc.get_context()->EvalMultDivision(c1, c2, bits, slots, cc.publicKey);
        for (int i = 0; i < reps - 1; i++)
        {
            cc.get_context()->EvalMultDivision(c1, c2, bits, slots, cc.publicKey);
        }

        std::cout << "Quotient (a / b)" << endl;
        if (verbose >= 2)
        {
            std::cout << "Expected: " << to_string_uint128(div_simd(a, b)) << endl;
            std::cout << "Obtained: " << cc.print_ints(cdiv, bits, slots);
            std::cout << endl;
        }
        if (verbose >= 1)
            print_duration(time, to_string(reps) + " quotients took on average: ", reps);
        std::cout << "-----" << endl;
    }
}

void precompute_stuff()
{
    int deg = 119;
    int bits = wordsize;

    if (bits <= 16)
    {
        deg = 59;
    }
    else if (bits == 32)
    {
        deg = 59;
    }
    else if (bits == 64)
    {
        deg = 119;
    }
    else if (bits == 128)
    {
        deg = 223;
    }
    else if (bits > 128)
    {
        deg = 425;
    }

    std::function<double(double)> sinc = [](double x) -> double
    {
        if (x == 0)
            return 0;
        return std::sin(x * M_PI) / (x * M_PI);
    };

    coeffsSinc = cc.get_context()->GetChebyshevCoefficients(sinc, 0, bits, deg);

    // Mults

    vector<vector<double>> coeffs;

    coeffs.push_back(read_vector_file("../coeffs/p1-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p2-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p3-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p4-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p5-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p6-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p7-norm-369.txt"));
    coeffs.push_back(read_vector_file("../coeffs/p8-norm-369.txt"));

    vector<vector<double>> slots_coeffs;

    for (int i = 0; i < (1 << (ring_size - 1)); ++i)
    {
        slots_coeffs.push_back(coeffs[i % coeffs.size()]);
    }

    auto a = cc.encrypt(cc.encode(0));

    cc.get_context()->ProcessMultiplications(slots_coeffs, a);

    int zslots = cc.get_context()->GetRingDimension() / (bits * bits);

    vector<vector<double>> coeffsBitLength;
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p1-norm-247-LUT-DIVISION.txt"));
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p2-norm-247-LUT-DIVISION.txt"));
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p3-norm-247-LUT-DIVISION.txt"));
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p4-norm-247-LUT-DIVISION.txt"));
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p5-norm-247-LUT-DIVISION.txt"));
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p6-norm-247-LUT-DIVISION.txt"));
    coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p7-norm-247-LUT-DIVISION.txt"));

    // Garbage padding: bits - 7 colonne aggiuntive, per arrivare a `bits` colonne totali
    for (int i = 0; i < bits - 7; i++)
        coeffsBitLength.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/lut/p1-norm-247-LUT-DIVISION.txt"));

    for (int i = 0; i < coeffsBitLength.size(); i++)
    {
        for (int j = 0; j < coeffsBitLength[i].size(); j++)
        {
            if (std::abs(coeffsBitLength[i][j]) < 1e-14)
            {
                // coeffsBitLength[i][j] = 0;
            }
        }
    }

    vector<vector<double>> coeffsLut;
    for (int i = 0; i < bits + 2; i++)
        coeffsLut.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/division/LUT-DIVISION-" + to_string(bits) + "-bits-" + to_string(i) + ".txt"));
    for (int i = 0; i < (bits * bits / 2) - (bits + 2); i++)
        coeffsLut.push_back(read_vector_file("../coeffs/LUTs/" + to_string(bits) + " bits/division/LUT-DIVISION-" + to_string(bits) + "-bits-0.txt")); // Garbage

    cc.get_context()->DivIntegerPrecomputations(a, bits, zslots, cc.publicKey, 1, coeffsBitLength, coeffsLut);

    Ctxt c1 = cc.encrypt(cc.encode({0}, startinglevel));
    Ctxt c2 = cc.encrypt(cc.encode({0}, startinglevel));
    int slots = cc.get_context()->GetRingDimension() / (bits * bits);
    cc.get_context()->EvalMultDivision(c1, c2, bits, slots, cc.publicKey);
}

void read_arguments(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];
        if (arg == "--ring" && i + 1 < argc)
        {
            ring_size = stoi(argv[i + 1]);
            ++i;
        }
        if (arg == "--verbose" && i + 1 < argc)
        {
            verbose = stoi(argv[i + 1]);
            ++i;
        }
        if (arg == "--bits" && i + 1 < argc)
        {
            wordsize = stoi(argv[i + 1]);

            if (wordsize != 8 && wordsize != 16 && wordsize != 32 && wordsize != 64 && wordsize != 128 &&
                wordsize != 256)
            {
                cerr << "The amount of bits (" << wordsize
                     << ") is not supported. Pick one out of (8, 16, 32, 64, 128, 256)" << endl;
            }

            ++i;
        }
        if (arg == "--test")
        {
            cout << "The program has been compiled and linked successfully, now checking if keygen works..." << endl;
            test = true;
        }
        if (arg == "--mev")
        {
            mev = true;
        }
        if (arg == "--hash")
        {
            ascon = true;
        }
        if (arg == "--noise")
        {
            noise_estimate = true;
        }
        if (arg == "--input")
        {
            input_mode = true;
        }
    }
}