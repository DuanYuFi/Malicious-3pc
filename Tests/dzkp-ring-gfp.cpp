#include "dzkp-gfp.h"
#include "../Processor/BaseMachine.h"
#include "../Math/gfp.h"
#include "../Tools/ezOptionParser.h"

#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace::std;

static const int FIELD_BITLEN = 160;
static const int M = 10000000;
static const int N_HBITS = 65 + log(M);
static const int STA_SEC = 40;
static const int IP_LEN = 2 * M + N_HBITS * STA_SEC;
static gfp TWO_POW64_GFP;
static gfp TWO_POW64_GFP_INV;
static gfp ZERO_GFP;
static gfp ONE_GFP;
static gfp* TWO_POWS;

uint64_t get_rand_uint64() {
    uint64_t tmp;
    tmp = rand();
    return ((uint64_t)rand()) + (tmp<<32);
}

ArithDZKProof arith_prove(
    gfp* triple_left, 
    gfp* triple_right, 
    gfp** masks,
    bool** higherbits_prev,
    bool** higherbits_next,
    bool** lambdas,
    uint64_t k, 
    gfp sid
) {
    cout << "In arith_prove()..." << endl;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    gfp eta = transcript_hash.get_challenge();

    // cout << "checkpoint 1, s: " << s << ", m: " << m << endl;
    // auto start = std::chrono::high_resolution_clock::now();

    // Random combination over ring and fields 
    gfp tmp = ONE_GFP;
    gfp *eta_powers = new gfp[STA_SEC];
    for(int i = 0; i < STA_SEC; i++) {
        eta_powers[i] = tmp;
        tmp *= eta;
    }

    // auto end = std::chrono::high_resolution_clock::now();
    // cout << "Computing eta_powers Time: " << (end - start).count() / 1e6 << " ms" << endl;

    auto start = std::chrono::high_resolution_clock::now();

    tmp = ZERO_GFP;
    // chrono::duration<double> diff_sum(0), diff_mul(0);
    gfp *merged_input_left = new gfp[IP_LEN], *merged_input_right = new gfp[IP_LEN];
    // int cnt = 0;
    for(int i = 0; i < M; i++) {
        // auto start1 = std::chrono::high_resolution_clock::now();
        tmp = ZERO_GFP;
        for(int j = 0; j < STA_SEC; j++) {
            if(lambdas[i][j]) {
                // cnt++;
                tmp += eta_powers[j];
            }
        }
        // auto end1 = std::chrono::high_resolution_clock::now();
        // diff_sum += end1 - start1;

        // start1 = std::chrono::high_resolution_clock::now();

        merged_input_left[2 * i] = tmp * triple_left[2 * i];
        merged_input_left[2 * i + 1] = tmp * triple_left[2 * i + 1];
        merged_input_right[2 * i] = triple_right[2 * i];
        merged_input_right[2 * i + 1] = triple_right[2 * i + 1];

        // end1 = std::chrono::high_resolution_clock::now();
        // diff_mul += end1 - start1;
    }
    // cout << "cnt: " << cnt << endl;

    auto end = std::chrono::high_resolution_clock::now();
    cout << "Linear Combining Inputs Time: " << (end - start).count() / 1e6 << " ms" << endl;
    // cout << "   Sum eta_powers Time: " << diff_sum.count() * 1e3 << " ms" << endl;
    // cout << "   Mul Time: " << diff_mul.count() * 1e3 << " ms" << endl;


    start = std::chrono::high_resolution_clock::now();

    for(int i = 0; i < STA_SEC; i++) {
        for(int j = 0; j < N_HBITS; j++) {
            if(higherbits_prev[i][j]) {
                merged_input_left[2 * M + i * STA_SEC + j] = eta_powers[j] * TWO_POWS[j];
            } else {
                merged_input_left[2 * M + i * STA_SEC + j] = ZERO_GFP;
            }
            if(higherbits_next[i][j]) {
                merged_input_right[2 * M + i * STA_SEC + j] = TWO_POWS[j];
            } else {
                merged_input_right[2 * M + i * STA_SEC + j] = ZERO_GFP;
            }
        }
    }
    
    end = std::chrono::high_resolution_clock::now();
    cout << "Mul HigherBits Share Time: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
    // Compute inputs for dzkp
    gfp **input_left = new gfp*[k], **input_right = new gfp*[k];

    uint64_t ip_len = ((IP_LEN - 1) / k + 1) * k;
    uint64_t s = (ip_len - 1) / k + 1;

    uint64_t temp_pointer = 0;

    for(int i = 0; i < k; i++) {
        input_left[i] = new gfp[s];
        input_right[i] = new gfp[s];

        for(int j = 0; j < s; j++) {
            if (temp_pointer >= IP_LEN) {
                input_left[i][j] = ZERO_GFP;
                input_right[i][j] = ZERO_GFP;
            } else {
                input_left[i][j] = merged_input_left[temp_pointer];
                input_right[i][j] = merged_input_right[temp_pointer];
            }
            temp_pointer++;
        }
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "Shaping Inputs Time: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
    // Vectors of masked evaluations of polynomial p(X)
    vector<vector<gfp>> p_evals_masked;
    // Evaluations of polynomial p(X)
    gfp* eval_p_poly = new gfp[2 * k - 1];  

    gfp** base = new gfp*[k - 1];
    for(uint64_t i = 0; i < k - 1; i++) {
        base[i] = new gfp[k];
    }
    // Langrange::get_bases(k, base);
    
    gfp* eval_base = new gfp[k];
    gfp** eval_result = new gfp*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = (gfp*)calloc(k, sizeof(gfp));
    }

    size_t index = 0;
    uint64_t round_id = 0;
    uint64_t s0 = s;

    // chrono::duration<double> diff_p(0), diff_f(0);
    while(true){
        // auto start1 = std::chrono::high_resolution_clock::now();

        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                for(uint64_t l = 0; l < s; l++) {
                    eval_result[i][j] += input_left[i][l] * input_right[j][l];
                }
            }
        }

        for(uint64_t i = 0; i < k; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(uint64_t i = 0; i < k - 1; i++) {
            eval_p_poly[i + k] = 0;
            for(uint64_t j = 0; j < k; j++) {
                for(uint64_t l = 0; l < k; l++) {
                    eval_p_poly[i + k] = eval_p_poly[i + k] + base[i][j] * eval_result[j][l] * base[i][l];
                }
            }
        } 

        vector<gfp> ss(2 * k - 1);       
        for(uint64_t i = 0; i < 2 * k - 1; i++) {           
            ss[i] = eval_p_poly[i] - masks[round_id][i];
        }
        p_evals_masked.push_back(ss);

        // auto end1 = std::chrono::high_resolution_clock::now();
        // diff_p += end1 - start1;

        if (s == 1) {
            break;
        }
        
        // start1 = std::chrono::high_resolution_clock::now();

        transcript_hash.append_msges(ss);
        gfp r = transcript_hash.get_challenge();

        Langrange::evaluate_bases(k, r, eval_base);

        s0 = s;
        s = (s - 1) / k + 1;
       
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
               
                if (index < s0) {
                    gfp temp_result;
                    temp_result = ZERO_GFP;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input_left[l][index];
                    }
                    input_left[i][j] = temp_result;

                    temp_result = ZERO_GFP;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input_right[l][index];
                    }
                    input_right[i][j] = temp_result;
                }
                else {
                    input_left[i][j] = ZERO_GFP;
                    input_right[i][j] = ZERO_GFP;
                }
            }
        }
        round_id++;
        
        // end1 = std::chrono::high_resolution_clock::now();
        // diff_f += end1 - start1;
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "Recursion Time: " << (end - start).count() / 1e6 << " ms" << endl;

    // cout << "   Evaluating p(X) Time: " << diff_p.count() * 1e3 << " ms" << endl;
    // cout << "   Evaluating f(r) Time: " << diff_f.count() * 1e3 << " ms" << endl;

    for(uint64_t i = 0; i < k; i++) {
        delete[] eval_result[i];
    }
    delete[] eval_result;
    delete[] eval_p_poly;

    for(uint64_t i = 0; i < k - 1; i++) {
        delete[] base[i];
    }
    delete[] base;
    delete[] eval_base;

    for(uint64_t i = 0; i < k; i++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for(int j = 0; j < round_id; j ++) {
        delete[] masks[j];
    }
    delete[] masks;

    ArithDZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

ArithVerMsg arith_gen_vermsg(
    ArithDZKProof proof, 
    gfp* triple_input,
    gfp* triple_input_mono,
    bool** higherbits_ss,
    bool** lambdas,
    gfp** masks_ss,
    uint64_t k, 
    gfp sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
   
    uint64_t ip_len = ((IP_LEN - 1) / k + 1) * k;
    uint64_t n_rounds = log(ip_len) / log(k) + 1;

    vector<gfp> b_ss(n_rounds);
    gfp final_input, final_result_ss;
    final_input = ZERO_GFP, final_result_ss = ZERO_GFP;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    gfp eta = transcript_hash.get_challenge();
    uint64_t round_id = 0;

    auto start = std::chrono::high_resolution_clock::now();

    gfp tmp = ONE_GFP;
    gfp *eta_powers = new gfp[STA_SEC];
    for(int i = 0; i < STA_SEC; i++) {
        eta_powers[i] = tmp;
        tmp *= eta;
    }

    gfp out_ss = ZERO_GFP;

    gfp *merged_input = new gfp[IP_LEN];
    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;
    if(!prev_party) {
        for(int i = 0; i < M; i++) {
            tmp = ZERO_GFP;
            // int cnt = 0;
            for(int j = 0; j < STA_SEC; j++) {
                if(lambdas[i][j]) {
                    tmp += eta_powers[j];
                    // cnt++;
                }
            }
            // cout << cnt << endl;
            merged_input[2 * i] = tmp * triple_input[2 * i];
            merged_input[2 * i + 1] = tmp * triple_input[2 * i + 1];
            out_ss += tmp * triple_input_mono[i];
        }
        for(int i = 0; i < STA_SEC; i++) {
            for(int j = 0; j < N_HBITS; j++) {
                if(higherbits_ss[i][j]) {
                    tmp = eta_powers[j] * TWO_POWS[j];
                    merged_input[2 * M + i * STA_SEC + j] = tmp;
                    out_ss += tmp;
                } else {
                    merged_input[2 * M + i * STA_SEC + j] = ZERO_GFP;
                }
            }
        }
    } else {
        for(int i = 0; i < M; i++) {
            merged_input[2 * i] = triple_input[2 * i];
            merged_input[2 * i + 1] = triple_input[2 * i + 1];

            tmp = ZERO_GFP;
            for(int j = 0; j < STA_SEC; j++) {
                if(lambdas[i][j]) {
                    tmp += eta_powers[j];
                }
            }
            out_ss += tmp * triple_input_mono[i];
        }
        for(int i = 0; i < STA_SEC; i++) {
            for(int j = 0; j < N_HBITS; j++) {
                if(higherbits_ss[i][j]) {
                    merged_input[2 * M + i * STA_SEC + j] = TWO_POWS[j];
                    out_ss += eta_powers[j] * TWO_POWS[j];
                } else {
                    merged_input[2 * M + i * STA_SEC + j] = ZERO_GFP;
                }
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    cout << "Linear Combining Inputs Time: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    // Compute inputs for dzkp
    gfp **input = new gfp*[k];


    uint64_t temp_pointer = 0;
    uint64_t s = (ip_len - 1) / k + 1;

    for(int i = 0; i < k; i++) {
        input[i] = new gfp[s];

        for(int j = 0; j < s; j++) {
            if (temp_pointer >= IP_LEN) {
                input[i][j] = ZERO_GFP;
            } else {
                input[i][j] = merged_input[temp_pointer];
            }
            temp_pointer++;
            // cout << "chcekpoint 3" << endl;
        }
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "Shaping Inputs Time: " << (end - start).count() / 1e6 << " ms" << endl;

    // start = std::chrono::high_resolution_clock::now();

    
    // end = std::chrono::high_resolution_clock::now();
    // cout << "Linear Combining Input Mono Time: " << (end - start).count() / 1e6 << " ms" << endl;

    // start = std::chrono::high_resolution_clock::now();


    // end = std::chrono::high_resolution_clock::now();
    // cout << "Combining HigherBits Time: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
    
    gfp sum_ss = ZERO_GFP;
    for(uint64_t j = 0; j < k; j++) { 
        sum_ss += proof.p_evals_masked[round_id][j];
    }
    b_ss[round_id] = sum_ss - out_ss;

    if(prev_party) {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[round_id][i] = proof.p_evals_masked[round_id][i] + masks_ss[round_id][i];
        } 
    } else {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[round_id][i] = masks_ss[round_id][i];
        }
    }
    
    gfp* eval_base = new gfp[k];
    gfp* eval_base_2k = new gfp[2 * k - 1];

    size_t index = 0;
    uint64_t s0 = s;
    gfp r;

    while(true)
    {
        transcript_hash.append_msges(proof.p_evals_masked[round_id]);

        if(prev_party) {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[round_id][i] = proof.p_evals_masked[round_id][i] + masks_ss[round_id][i];
            } 
        } else {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[round_id][i] = masks_ss[round_id][i];
            }
        }
        sum_ss = ZERO_GFP;
        for(uint64_t j = 0; j < k; j++) { 
            sum_ss += proof.p_evals_masked[round_id][j];
        }

        r = transcript_hash.get_challenge();
        Langrange::evaluate_bases(2 * k - 1, r, eval_base_2k);
        out_ss = ZERO_GFP;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            out_ss += eval_base_2k[i] * proof.p_evals_masked[round_id][i];
        }

        b_ss[round_id] = sum_ss - out_ss;

        if(s == 1) {
            r = transcript_hash.get_challenge();
            Langrange::evaluate_bases(k, r, eval_base);
            
            for(uint64_t i = 0; i < k; i++) {
                final_input += eval_base[i] * input[i][0];
            }
            Langrange::evaluate_bases(2 * k - 1, r, eval_base_2k);

            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                final_result_ss += eval_base_2k[i] * proof.p_evals_masked[round_id][i];
            }

            break;
        }

        Langrange::evaluate_bases(k, r, eval_base);
        s0 = s;
        s = (s - 1) / k + 1;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    gfp temp_result;
                    temp_result = ZERO_GFP;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input[l][index];
                    }
                    input[i][j] = temp_result;
                }
                else {
                    input[i][j] = ZERO_GFP;
                }
            }
        }
        round_id++;
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "Recursion Time: " << (end - start).count() / 1e6 << " ms" << endl;


    delete[] eval_base;
    delete[] eval_base_2k;

    for(uint64_t i = 0; i < k; i++) {
        delete[] input[i];
    }
    delete[] input;

    delete[] triple_input;
    delete[] triple_input_mono;

    for(int j = 0; j < round_id; j ++) {
        delete[] masks_ss[j];
    }
    delete[] masks_ss;

    ArithVerMsg vermsg(
        b_ss,
        final_input,
        final_result_ss
    );
    return vermsg;
}

bool arith_verify(
    ArithDZKProof proof, 
    ArithVerMsg other_vermsg, 
    gfp* triple_input,
    gfp* triple_input_mono,
    bool** higherbits_ss,
    bool** lambdas,
    gfp** masks_ss,
    uint64_t k, 
    gfp sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    cout << "in arith_verify()..." << endl;
    
    uint64_t ip_len = ((IP_LEN - 1) / k + 1) * k;
    uint64_t n_rounds = log(ip_len) / log(k) + 1;
    
    ArithVerMsg self_vermsg = arith_gen_vermsg(proof, triple_input, triple_input_mono, higherbits_ss, lambdas, masks_ss, k, sid, prover_ID, party_ID);

    gfp b;

    for(uint64_t i = 0; i < n_rounds; i++) {
        b = self_vermsg.b_ss[i] + other_vermsg.b_ss[i];
        
        if(!b.is_zero()) {    
            // cout << "b != 0 at index " << i << endl; 
            return false;
        }
    }
    gfp res = self_vermsg.final_input + other_vermsg.final_input;
    gfp p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    
    if(res != p_eval_r) {   
        // cout << "res != p_eval_r" << endl;
        return false;
    } 

    // cout << "out of arith_verify..." << endl;
    return true;
}

void get_higher_bits(gfp* triple_left, gfp* triple_right, gfp* triple_mono_prev, gfp* triple_mono_next, bool** higherbits, bool** lambdas)
{
    gfp* highers = new gfp[M];
    for(int i = 0; i < M; i++) {
        highers[i] = triple_left[2 * i] * triple_right[2 * i] + triple_left[2 * i + 1] * triple_right[2 * i + 1] - triple_mono_prev[i] - triple_mono_next[i];
    }
    
    for(int i = 0; i < STA_SEC; i++) {
        gfp h = ZERO_GFP;
        for(int j = 0; j < M; j++) {
            if(lambdas[j][i]) {
                h += highers[j];
            }
        }
        h *= TWO_POW64_GFP_INV;
        for(int j = 0; j < N_HBITS; j++) {
            higherbits[i][j] = gfp(bigint(h >> j) & 1).is_zero() ? 0 : 1;
        }
    }  
}

void share_higherbits(bool** higherbits, bool** higherbits_prev, bool** higherbits_next)
{
    for(int i = 0; i < STA_SEC; i++) {
        for(int j = 0; j < N_HBITS; j++) {
            higherbits_prev[i][j] = rand() & 1;
            higherbits_next[i][j] = higherbits[i][j] ^ higherbits_prev[i][j];
        }
    }
}

int main() {

    // gfp::init_field("1248068881904942296572604080834739402838498312531");
    gfp::init_field(SPDZ_Data_Setup_Primes(FIELD_BITLEN));

    TWO_POW64_GFP = gfp("18446744073709551616");
    TWO_POW64_GFP_INV = TWO_POW64_GFP.invert();
    ZERO_GFP = gfp(0);
    ONE_GFP = gfp(1);

    TWO_POWS = new gfp[N_HBITS];
    gfp two_power = TWO_POW64_GFP;
    for(int i = 0; i < N_HBITS; i++) {
        two_power = two_power << 1;
        TWO_POWS[i] = two_power;
    }

    srand(time(0));
    PRNG prng;
    prng.ReSeed();

    uint64_t k = 8;

    uint64_t ip_len = ((IP_LEN - 1) / k + 1) * k;
    int n_rounds = log(ip_len) / log(k) + 1;

    // cout << "checkpoint 0" << endl;

    // Generate masks
    gfp **masks, **masks_prev, **masks_next;
    masks = new gfp*[n_rounds];
    masks_prev = new gfp*[n_rounds];
    masks_next = new gfp*[n_rounds];

    for(int i = 0; i < n_rounds; i++) {
        masks[i] = new gfp[2 * k - 1];
        masks_prev[i] = new gfp[2 * k - 1];
        masks_next[i] = new gfp[2 * k - 1];

        for(int j = 0; j < 2 * k - 1; j++) {
            masks_prev[i][j].randomize(prng);
            masks_next[i][j].randomize(prng);
            masks[i][j] = masks_prev[i][j] + masks_next[i][j];
        }
    }

    // cout << "checkpoint 1" << endl;

    // Generate mul triples
    gfp *triple_left, *triple_right, *triple_mono_prev, *triple_mono_next;
    triple_left = new gfp[2 * M];
    triple_right = new gfp[2 * M];
    triple_mono_prev = new gfp[M];
    triple_mono_next = new gfp[M];

    int temp_pointer = 0; 

    for(int i = 0; i < M; i++) {
        uint64_t x_first, x_second, y_first, y_second, rho_first, rho_second;
        x_first = get_rand_uint64();
        x_second = get_rand_uint64();
        y_first = get_rand_uint64();
        y_second = get_rand_uint64();
        rho_first = get_rand_uint64();
        rho_second = get_rand_uint64();
        uint64_t z = x_first * (y_first + y_second) + x_second * y_first + rho_first - rho_second;

        triple_left[2 * i] = gfp(x_first);
        triple_left[2 * i + 1] = gfp(y_first);
        triple_right[2 * i] = gfp(x_second);
        triple_right[2 * i + 1] = gfp(y_second);
        triple_mono_prev[i] = gfp(z - x_first * y_first - rho_first);
        triple_mono_next[i] = gfp(rho_second);
    }

    // cout << "checkpoint 2" << endl;

    bool** lambdas = new bool*[M];
    for(int i = 0; i < M; i++) {
        lambdas[i] = new bool[STA_SEC];
        for(int j = 0; j < STA_SEC; j++) {
            lambdas[i][j] = rand() & 1;
            // cout << lambdas[i][j] << endl;
        }
    }

    // Compute higher bits
    bool **higherbits = new bool*[STA_SEC];
    for(int i = 0; i < STA_SEC; i++) {
        higherbits[i] = new bool[N_HBITS];
    }

    auto start = std::chrono::high_resolution_clock::now();
    get_higher_bits(triple_left, triple_right, triple_mono_prev, triple_mono_next, higherbits, lambdas);
    auto end = std::chrono::high_resolution_clock::now();
    
    cout << "Computing HigherBits Time: " << (end - start).count() / 1e6 << " ms" << endl;
    cout << endl;

    // cout << "checkpoint 3" << endl;

    // Share higher bits
    bool **higherbits_prev = new bool*[STA_SEC];
    bool **higherbits_next = new bool*[STA_SEC];
    for(int i = 0; i < STA_SEC; i++) {
        higherbits_prev[i] = new bool[N_HBITS];
        higherbits_next[i] = new bool[N_HBITS];
    }
    share_higherbits(higherbits, higherbits_prev, higherbits_next);

    // cout << "checkpoint 4" << endl;

    gfp sid;
    sid.randomize(prng);

    auto start = std::chrono::high_resolution_clock::now();
    ArithDZKProof proof = arith_prove(triple_left, triple_right, masks, higherbits_prev, higherbits_next, lambdas, k, sid);
    auto end = std::chrono::high_resolution_clock::now();
    cout << "Proving time: " << (start - end).count() / 1e6 << " ms" << endl;
    cout << endl;

    start = std::chrono::high_resolution_clock::now();
    ArithVerMsg other_vermsg = arith_gen_vermsg(proof, triple_left, triple_mono_next, higherbits_next, lambdas, masks_next, k, sid, 0, 1);
    bool res = arith_verify(proof, other_vermsg, triple_right, triple_mono_prev, higherbits_prev, lambdas, masks_prev, k, sid, 0, 2);
    end = std::chrono::high_resolution_clock::now();
    cout << "Verifying time: " << (start - end).count() / 1e6 << " ms" << endl;

    // cout << "res: " << res << endl;
    return 0;
} 

