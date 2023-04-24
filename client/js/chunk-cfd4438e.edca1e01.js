(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["chunk-cfd4438e"],{

/***/ "001f":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


__webpack_require__("d9e2");
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.throwError = void 0;
function throwError(message) {
  throw new Error(message);
}
exports.throwError = throwError;

/***/ }),

/***/ "00e3":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.shake256 = exports.shake128 = exports.keccak_512 = exports.keccak_384 = exports.keccak_256 = exports.keccak_224 = exports.sha3_512 = exports.sha3_384 = exports.sha3_256 = exports.sha3_224 = exports.Keccak = exports.keccakP = void 0;
const _assert_js_1 = __webpack_require__("b40a");
const _u64_js_1 = __webpack_require__("5220");
const utils_js_1 = __webpack_require__("531d");
// Various per round constants calculations
const [SHA3_PI, SHA3_ROTL, _SHA3_IOTA] = [[], [], []];
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    // Pi
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
    // Iota
    let t = _0n;
    for (let j = 0; j < 7; j++) {
        R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
        if (R & _2n)
            t ^= _1n << ((_1n << BigInt(j)) - _1n);
    }
    _SHA3_IOTA.push(t);
}
const [SHA3_IOTA_H, SHA3_IOTA_L] = _u64_js_1.default.split(_SHA3_IOTA, true);
// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s) => s > 32 ? _u64_js_1.default.rotlBH(h, l, s) : _u64_js_1.default.rotlSH(h, l, s);
const rotlL = (h, l, s) => s > 32 ? _u64_js_1.default.rotlBL(h, l, s) : _u64_js_1.default.rotlSL(h, l, s);
// Same as keccakf1600, but allows to skip some rounds
function keccakP(s, rounds = 24) {
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
        // Theta θ
        for (let x = 0; x < 10; x++)
            B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        for (let x = 0; x < 10; x += 2) {
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
            for (let y = 0; y < 50; y += 10) {
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for (let t = 0; t < 24; t++) {
            const shift = SHA3_ROTL[t];
            const Th = rotlH(curH, curL, shift);
            const Tl = rotlL(curH, curL, shift);
            const PI = SHA3_PI[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        for (let y = 0; y < 50; y += 10) {
            for (let x = 0; x < 10; x++)
                B[x] = s[y + x];
            for (let x = 0; x < 10; x++)
                s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H[round];
        s[1] ^= SHA3_IOTA_L[round];
    }
    B.fill(0);
}
exports.keccakP = keccakP;
class Keccak extends utils_js_1.Hash {
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        super();
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.rounds = rounds;
        this.pos = 0;
        this.posOut = 0;
        this.finished = false;
        this.destroyed = false;
        // Can be passed from user as dkLen
        _assert_js_1.default.number(outputLen);
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        if (0 >= this.blockLen || this.blockLen >= 200)
            throw new Error('Sha3 supports only keccak-f1600 function');
        this.state = new Uint8Array(200);
        this.state32 = (0, utils_js_1.u32)(this.state);
    }
    keccak() {
        keccakP(this.state32, this.rounds);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        _assert_js_1.default.exists(this);
        const { blockLen, state } = this;
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
                state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
                this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished)
            return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // Do the padding
        state[pos] ^= suffix;
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1)
            this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        _assert_js_1.default.exists(this, false);
        _assert_js_1.default.bytes(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len;) {
            if (this.posOut >= blockLen)
                this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
        if (!this.enableXOF)
            throw new Error('XOF is not possible for this instance');
        return this.writeInto(out);
    }
    xof(bytes) {
        _assert_js_1.default.number(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        _assert_js_1.default.output(out, this);
        if (this.finished)
            throw new Error('digest() was already called');
        this.writeInto(out);
        this.destroy();
        return out;
    }
    digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
        this.destroyed = true;
        this.state.fill(0);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to || (to = new Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        to.destroyed = this.destroyed;
        return to;
    }
}
exports.Keccak = Keccak;
const gen = (suffix, blockLen, outputLen) => (0, utils_js_1.wrapConstructor)(() => new Keccak(blockLen, suffix, outputLen));
exports.sha3_224 = gen(0x06, 144, 224 / 8);
/**
 * SHA3-256 hash function
 * @param message - that would be hashed
 */
exports.sha3_256 = gen(0x06, 136, 256 / 8);
exports.sha3_384 = gen(0x06, 104, 384 / 8);
exports.sha3_512 = gen(0x06, 72, 512 / 8);
exports.keccak_224 = gen(0x01, 144, 224 / 8);
/**
 * keccak-256 hash function. Different from SHA3-256.
 * @param message - that would be hashed
 */
exports.keccak_256 = gen(0x01, 136, 256 / 8);
exports.keccak_384 = gen(0x01, 104, 384 / 8);
exports.keccak_512 = gen(0x01, 72, 512 / 8);
const genShake = (suffix, blockLen, outputLen) => (0, utils_js_1.wrapConstructorWithOpts)((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true));
exports.shake128 = genShake(0x1f, 168, 128 / 8);
exports.shake256 = genShake(0x1f, 136, 256 / 8);
//# sourceMappingURL=sha3.js.map

/***/ }),

/***/ "0302":
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__.p + "client/img/top-dog@2x.504b4e5e.png";

/***/ }),

/***/ "0366":
/***/ (function(module, exports, __webpack_require__) {

var uncurryThis = __webpack_require__("4625");
var aCallable = __webpack_require__("59ed");
var NATIVE_BIND = __webpack_require__("40d5");

var bind = uncurryThis(uncurryThis.bind);

// optional / simple context binding
module.exports = function (fn, that) {
  aCallable(fn);
  return that === undefined ? fn : NATIVE_BIND ? bind(fn, that) : function (/* ...args */) {
    return fn.apply(that, arguments);
  };
};


/***/ }),

/***/ "059d":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Banner_vue_vue_type_style_index_0_id_489ee243_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("7357");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Banner_vue_vue_type_style_index_0_id_489ee243_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Banner_vue_vue_type_style_index_0_id_489ee243_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "0807":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_MyAssets_vue_vue_type_style_index_0_id_ad6dd15a_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("2c97");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_MyAssets_vue_vue_type_style_index_0_id_ad6dd15a_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_MyAssets_vue_vue_type_style_index_0_id_ad6dd15a_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "101e":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.StandardMerkleTree = void 0;
var standard_1 = __webpack_require__("6daf");
Object.defineProperty(exports, "StandardMerkleTree", {
  enumerable: true,
  get: function () {
    return standard_1.StandardMerkleTree;
  }
});

/***/ }),

/***/ "14d9":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var $ = __webpack_require__("23e7");
var toObject = __webpack_require__("7b0b");
var lengthOfArrayLike = __webpack_require__("07fa");
var setArrayLength = __webpack_require__("3a34");
var doesNotExceedSafeInteger = __webpack_require__("3511");
var fails = __webpack_require__("d039");

var INCORRECT_TO_LENGTH = fails(function () {
  return [].push.call({ length: 0x100000000 }, 1) !== 4294967297;
});

// V8 and Safari <= 15.4, FF < 23 throws InternalError
// https://bugs.chromium.org/p/v8/issues/detail?id=12681
var properErrorOnNonWritableLength = function () {
  try {
    // eslint-disable-next-line es/no-object-defineproperty -- safe
    Object.defineProperty([], 'length', { writable: false }).push();
  } catch (error) {
    return error instanceof TypeError;
  }
};

var FORCED = INCORRECT_TO_LENGTH || !properErrorOnNonWritableLength();

// `Array.prototype.push` method
// https://tc39.es/ecma262/#sec-array.prototype.push
$({ target: 'Array', proto: true, arity: 1, forced: FORCED }, {
  // eslint-disable-next-line no-unused-vars -- required for `.length`
  push: function push(item) {
    var O = toObject(this);
    var len = lengthOfArrayLike(O);
    var argCount = arguments.length;
    doesNotExceedSafeInteger(len + argCount);
    for (var i = 0; i < argCount; i++) {
      O[len] = arguments[i];
      len++;
    }
    setArrayLength(O, len);
    return len;
  }
});


/***/ }),

/***/ "16c0":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/index.vue?vue&type=template&id=a1a8b50e&scoped=true&
var render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"home"},[_c('Banner'),_c('Marshmallow'),_c('Invitation'),_c('Recommend'),_c('CommonProblem')],1)}
var staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/index.vue?vue&type=template&id=a1a8b50e&scoped=true&

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Banner.vue?vue&type=template&id=489ee243&scoped=true&
var Bannervue_type_template_id_489ee243_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"banner"},[_c('div',{staticClass:"bg"}),_c('b-container',{attrs:{"fluid":"lg"}},[_c('div',{staticClass:"left-content"},[_c('h3',[_vm._v(" GM! Musk, ")]),_c('p',[_vm._v("take your DOGE to the Moon with")]),_c('p',[_c('em',[_vm._v("Martin Quantization.")])]),_c('p',[_vm._v("So fucking exciting…")])])])],1)}
var Bannervue_type_template_id_489ee243_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/Banner.vue?vue&type=template&id=489ee243&scoped=true&

// EXTERNAL MODULE: ./src/views/Home/components/Banner.vue?vue&type=style&index=0&id=489ee243&prod&lang=scss&scoped=true&
var Bannervue_type_style_index_0_id_489ee243_prod_lang_scss_scoped_true_ = __webpack_require__("059d");

// EXTERNAL MODULE: ./node_modules/vue-loader/lib/runtime/componentNormalizer.js
var componentNormalizer = __webpack_require__("2877");

// CONCATENATED MODULE: ./src/views/Home/components/Banner.vue

var script = {}



/* normalize component */

var component = Object(componentNormalizer["a" /* default */])(
  script,
  Bannervue_type_template_id_489ee243_scoped_true_render,
  Bannervue_type_template_id_489ee243_scoped_true_staticRenderFns,
  false,
  null,
  "489ee243",
  null
  
)

/* harmony default export */ var Banner = (component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Marshmallow.vue?vue&type=template&id=01415f38&scoped=true&
var Marshmallowvue_type_template_id_01415f38_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"earn",attrs:{"id":"Earn"}},[_vm._m(0),_c('b-container',{attrs:{"fluid":"lg"}},[_c('h2',[_vm._v("Earn")]),_c('div',{staticClass:"earn-wrapper"},[_c('div',{staticClass:"slider-view",class:{
          'step-1': _vm.step === 1,
          'step-2': _vm.step === 2,
          'step-3': _vm.step === 3,
          'step-4': _vm.step === 4,
        }},[_c('div',{staticClass:"slider"},[_c('SubscribeSelect',{attrs:{"type":_vm.type},on:{"next":_vm.onNextOne}})],1),_c('div',{staticClass:"slider"},[_c('Subscribe',{attrs:{"type":_vm.type},on:{"change-step":_vm.onChangeStep}})],1),_c('div',{staticClass:"slider"},[_c('MyAssets',{on:{"change-step":_vm.onChangeStep}})],1),_c('div',{staticClass:"slider"},[(_vm.slideType === 'claim')?_c('Claim',{attrs:{"type":_vm.type},on:{"change-step":_vm.onChangeStep}}):_vm._e(),(_vm.slideType === 'reinvest')?_c('Reinvest',{attrs:{"type":_vm.type},on:{"change-step":_vm.onChangeStep}}):_vm._e()],1)])])])],1)}
var Marshmallowvue_type_template_id_01415f38_scoped_true_staticRenderFns = [function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"logo-wrapper"},[_c('img',{attrs:{"src":__webpack_require__("0302"),"alt":""}})])}]


// CONCATENATED MODULE: ./src/views/Home/components/Marshmallow.vue?vue&type=template&id=01415f38&scoped=true&

// EXTERNAL MODULE: ./node_modules/vuex/dist/vuex.esm.js
var vuex_esm = __webpack_require__("2f62");

// EXTERNAL MODULE: ./src/mixin/toastMixin.js
var toastMixin = __webpack_require__("ad84");

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/SubscribeSelect.vue?vue&type=template&id=32fd27c8&scoped=true&
var SubscribeSelectvue_type_template_id_32fd27c8_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',[_c('b-row',{staticClass:"marshmallow-container",attrs:{"align-h":"between"}},[_c('b-col',{staticClass:"left",attrs:{"lg":"6","order":"1","order-md":"1"}},[_c('div',{staticClass:"select-section",class:{active: _vm.active === 0},on:{"click":function($event){return _vm.changeInviteCard(0)}}},[_c('div',{staticClass:"select-top"},[_c('span',[_vm._v("Regular Interest")]),_c('span',[_vm._v("30 days")])]),_c('div',{staticClass:"select-middle"},[_vm._v(" APR："),_c('em',[_vm._v("72.00%+")])]),_c('div',{staticClass:"select-bottom"},[_vm._v(" Pay interest only when due ")])])]),_c('b-col',{staticClass:"right",attrs:{"lg":"6","order":"2","order-md":"2"}},[_c('div',{staticClass:"select-section",class:{active: _vm.active === 1},on:{"click":function($event){return _vm.changeInviteCard(1)}}},[_c('div',{staticClass:"select-top"},[_c('span',[_vm._v("Daily Interest")]),_c('span',[_vm._v("365 days")])]),_c('div',{staticClass:"select-middle"},[_vm._v(" APR："),_c('em',[_vm._v("120.00%+")])]),_c('div',{staticClass:"select-bottom"},[_vm._v(" Receive interest the next day ")])])])],1),_c('b-row',{attrs:{"align-h":"center"}},[(_vm.user.address)?_c('b-button',{staticClass:"subscribe-btn",attrs:{"variant":"primary"},on:{"click":_vm.subscribe}},[_vm._v("Subscribe")]):_c('b-button',{staticClass:"connect-btn",attrs:{"variant":"primary"},on:{"click":_vm.unlock}},[_vm._v("Connect Wallet")])],1)],1)}
var SubscribeSelectvue_type_template_id_32fd27c8_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/SubscribeSelect.vue?vue&type=template&id=32fd27c8&scoped=true&

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/SubscribeSelect.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//



/* harmony default export */ var SubscribeSelectvue_type_script_lang_js_ = ({
  components: {},
  mixins: [toastMixin["a" /* default */]],
  data() {
    return {
      active: 0
    };
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user'])
  },
  methods: {
    ...Object(vuex_esm["b" /* mapActions */])(['showComingSoon']),
    unlock() {
      this.$store.dispatch('unlockByMetaMask');
    },
    changeInviteCard(id) {
      this.active = id;
    },
    subscribe() {
      // console.log('xxxx');
      this.$emit('next', this.active);
      // this.showError('123123', {
      //   tx: '123'
      // });
    }
  }
});
// CONCATENATED MODULE: ./src/views/Home/components/SubscribeSelect.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_SubscribeSelectvue_type_script_lang_js_ = (SubscribeSelectvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/SubscribeSelect.vue?vue&type=style&index=0&id=32fd27c8&prod&lang=scss&scoped=true&
var SubscribeSelectvue_type_style_index_0_id_32fd27c8_prod_lang_scss_scoped_true_ = __webpack_require__("e2a9");

// CONCATENATED MODULE: ./src/views/Home/components/SubscribeSelect.vue






/* normalize component */

var SubscribeSelect_component = Object(componentNormalizer["a" /* default */])(
  components_SubscribeSelectvue_type_script_lang_js_,
  SubscribeSelectvue_type_template_id_32fd27c8_scoped_true_render,
  SubscribeSelectvue_type_template_id_32fd27c8_scoped_true_staticRenderFns,
  false,
  null,
  "32fd27c8",
  null
  
)

/* harmony default export */ var SubscribeSelect = (SubscribeSelect_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Subscribe.vue?vue&type=template&id=f04610f4&scoped=true&
var Subscribevue_type_template_id_f04610f4_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"subscribe"},[_c('b-row',{attrs:{"align-v":"start"}},[_c('b-col',{staticClass:"left-section",attrs:{"lg":"6"}},[_c('div',{staticClass:"content-row row-product"},[_c('div',{staticClass:"label"},[_vm._v("Product：")]),_c('div',{staticClass:"content"},[_c('span',[_vm._v(_vm._s(_vm.type === 0 ? 'Regular Interest' : 'Daily Interest'))]),_c('span',[_vm._v("APR: "),_c('em',[_vm._v(_vm._s(_vm.type === 0 ? '72.00%+' : '120.00%+'))])])])]),_c('div',{staticClass:"content-row row-amount"},[_c('div',{staticClass:"label"},[_vm._v("Amount：")]),_c('div',{staticClass:"content"},[_c('div',{staticClass:"content-left"},[_c('input',{directives:[{name:"model",rawName:"v-model.number",value:(_vm.amount),expression:"amount",modifiers:{"number":true}}],attrs:{"placeholder":("Balance: " + _vm.dogeAmount),"type":"number"},domProps:{"value":(_vm.amount)},on:{"input":[function($event){if($event.target.composing){ return; }_vm.amount=_vm._n($event.target.value)},_vm.onInput],"blur":function($event){return _vm.$forceUpdate()}}})]),_c('div',{staticClass:"content-right"},[_c('span',{staticClass:"max-btn",on:{"click":function($event){_vm.amount = _vm.max}}},[_vm._v("MAX")])])])]),_c('div',{staticClass:"content-row row-tip"},[_c('div',{staticClass:"content"},[_vm._v(" = $ "+_vm._s(_vm._f("toFixed")((_vm.amount * _vm.user.dogePrice / Math.pow( 10, _vm.user.dogePriceDecimals )),2))+" ")])]),_c('div',{staticClass:"content-row row-range"},[_c('div',{staticClass:"label"},[_vm._v("Operating range：")]),_c('div',{staticClass:"content"},[_c('span',[_vm._v("Min："+_vm._s(_vm.min)+" USDT")]),_c('span',[_vm._v("Max: "+_vm._s(_vm.max)+" USDT")])])]),_c('div',{staticClass:"content-row row-interest"},[_c('div',{staticClass:"label"},[_vm._v("Estimated interest：")]),_c('div',{staticClass:"content"},[_c('em',[_vm._v(_vm._s(_vm.interest)+" USDT")])])])]),_c('b-col',{staticClass:"right-section",attrs:{"lg":"6"}},[_c('div',{staticClass:"content-row row-operating"},[_c('div',{staticClass:"label"},[_vm._v("Interest payment：")]),_c('div',{staticClass:"content"},[_c('div',[_vm._v(" "+_vm._s(_vm.type === 0 ? 'Pay interest only due' : 'Daily Interest Payment')+" ")])])]),_c('div',{staticClass:"content-row"},[_c('div',{staticClass:"label"}),_c('div',{staticClass:"content"},[_c('div',{staticClass:"timeline"},[_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("Subscription date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.subscriptionDate))])]),_c('span',{staticClass:"line"}),_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("Accrual Start Date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.valueDate)+" 08:00:00")])]),_c('span',{staticClass:"line"}),_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("First Distribution Date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.interestDate)+" 08:00:00")])])])])])])],1),_c('b-row',{attrs:{"align-h":"center"}},[_c('div',{staticClass:"btn-wrapper"},[(!_vm.approved)?_c('b-button',{staticClass:"subscribe-btn",attrs:{"variant":"primary","disabled":_vm.submitting},on:{"click":_vm.onApprove}},[_vm._v("Approve "),(_vm.submitting)?_c('b-icon',{attrs:{"icon":"arrow-repeat","rotate":"45","animation":"spin"}}):_vm._e()],1):_c('b-button',{staticClass:"subscribe-btn",attrs:{"variant":"primary","disabled":_vm.submitting || !_vm.amount},on:{"click":_vm.onBuy}},[_vm._v("Subscribe "),(_vm.submitting)?_c('b-icon',{attrs:{"icon":"arrow-repeat","rotate":"45","animation":"spin"}}):_vm._e()],1),_c('b-button',{staticClass:"cancel-btn",on:{"click":_vm.onCancel}},[_vm._v("Cancel")])],1)])],1)}
var Subscribevue_type_template_id_f04610f4_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/Subscribe.vue?vue&type=template&id=f04610f4&scoped=true&

// EXTERNAL MODULE: ./node_modules/moment/moment.js
var moment = __webpack_require__("c1df");
var moment_default = /*#__PURE__*/__webpack_require__.n(moment);

// EXTERNAL MODULE: ./node_modules/@ethersproject/bignumber/lib.esm/bignumber.js
var bignumber = __webpack_require__("e36d");

// EXTERNAL MODULE: ./node_modules/@vue/composition-api/dist/vue-composition-api.mjs
var vue_composition_api = __webpack_require__("ed09");

// EXTERNAL MODULE: ./src/config/index.js + 3 modules
var config = __webpack_require__("f121");

// EXTERNAL MODULE: ./src/eth/ethereum.js
var ethereum = __webpack_require__("b88c");

// CONCATENATED MODULE: ./src/common/sendTransaction.js



const sendTransaction = async ({
  to,
  data,
  gas
}) => {
  const gasPrice = await ethereum["e" /* provider */].getGasPrice();
  // const txCount = await provider.getTransactionCount(ethereum.selectedAddress, 'pending');

  const transactionParameters = {
    // nonce: txCount, // ignored by MetaMask
    gasPrice: gasPrice.toHexString(),
    // customizable by user during MetaMask confirmation.
    gas: bignumber["a" /* BigNumber */].from(gas || 240000).toHexString(),
    // customizable by user during MetaMask confirmation.
    to,
    // Required except during contract publications.
    from: window.ethereum.selectedAddress,
    // must match user's active address.
    value: '0x00',
    // Only required to send ether to the recipient from the initiating external account.
    data,
    // Optional, but used for defining smart contract creation and interaction.
    chainId: config["a" /* default */].chainId // Used to prevent transaction reuse across blockchains. Auto-filled by MetaMask.
  };

  console.log(JSON.stringify(transactionParameters));
  // txHash is a hex string
  // As with any RPC call, it may throw an error
  const txHash = await window.ethereum.request({
    method: 'eth_sendTransaction',
    params: [transactionParameters]
  });
  return txHash;
};
/* harmony default export */ var common_sendTransaction = (sendTransaction);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Subscribe.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//








/* harmony default export */ var Subscribevue_type_script_lang_js_ = (Object(vue_composition_api["b" /* defineComponent */])({
  props: {
    type: {
      type: Number
    }
  },
  data() {
    const {
      refer
    } = this.$route.query;
    return {
      invitee: refer || config["a" /* default */].defaultInviter,
      submitting: false,
      amount: '',
      approved: false
    };
  },
  watch: {
    user: {
      handler() {
        if (this.user.address) {
          this.getAllowance();
        }
      },
      immediate: true
    }
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user']),
    dogeAmount() {
      const total = Math.floor(this.user.dogeBalance / 10 ** this.user.dogeDecimals);
      return total;
    },
    min() {
      if (this.user.positionOpened) {
        const min = Math.ceil((this.user.min - this.user.depositAmount) / this.user.dogePrice);
        return min < 0 ? 0 : min;
      }
      return Math.ceil(this.user.min / this.user.dogePrice);
    },
    max() {
      if (this.user.positionOpened) {
        return Math.ceil((this.user.max - this.user.depositAmount) / this.user.dogePrice);
      }
      return Math.ceil(this.user.max / this.user.dogePrice);
    },
    interest() {
      if (!this.amount) {
        return 0;
      }
      if (this.type === 0) {
        return Math.floor(this.amount * 0.72);
      }
      if (this.type === 1) {
        return Math.floor(this.amount * 1.2);
      }
    },
    subscriptionDate() {
      return moment_default()().format('yyyy-MM-DD HH:mm:ss');
    },
    valueDate() {
      return moment_default()().add(1, 'day').format('yyyy-MM-DD');
    },
    interestDate() {
      if (this.type === 0) {
        return moment_default()().add(30, 'day').format('yyyy-MM-DD');
      }
      if (this.type === 1) {
        return moment_default()().add(365, 'day').format('yyyy-MM-DD');
      }
    }
  },
  methods: {
    onInput(event) {
      let {
        value
      } = event.target;
      value = value.replace(/[^\d]/g, ''); // 只保留数字
      this.amount = parseInt(value, 10); // 转成数字类型
      if (this.amount > this.max) {
        this.amount = this.max;
      }
    },
    async getAllowance() {
      const allowance = await ethereum["a" /* dogeTokenContract */].allowance(this.user.address, config["a" /* default */].MartinDepositAddress);
      // console.log(allowance)
      this.approved = allowance.gt(100);
    },
    async onApprove() {
      this.submitting = true;
      try {
        const approveTxHash = await common_sendTransaction({
          to: config["a" /* default */].DogeTokenAddress,
          gas: 80000,
          data: ethereum["b" /* dogeTokenInterface */].encodeFunctionData('approve', [config["a" /* default */].MartinDepositAddress, bignumber["a" /* BigNumber */].from('9'.repeat(32)).toHexString()])
        });
        console.log('approveTxHash: ', approveTxHash);
        const approveTx = await ethereum["e" /* provider */].waitForTransaction(approveTxHash);
        console.log('approveTxHash finish');
        if (approveTx.status !== 1) {
          this.showError('Approve fail，please retry');
          this.submitting = false;
        } else {
          // this.showSuccess('Approve success');
          this.showSuccess('Success', {
            tx: approveTxHash
          });
          this.approved = true;
        }
      } catch (e) {
        console.error(e);
      } finally {
        this.submitting = false;
      }
    },
    async onBuy() {
      const {
        amount
      } = this;
      if (amount < this.min) {
        this.showError(`The minimum subscribe is ${this.min} USDT`);
        return;
      }
      if (!this.user.address) {
        this.showError('Please connect metamask');
        return false;
      }
      this.submitting = true;
      const dogeBalance = await ethereum["a" /* dogeTokenContract */].balanceOf(this.user.address);
      if (dogeBalance.lt(amount + '0'.repeat(this.user.dogeDecimals))) {
        this.showError('You balance is not enough');
        this.submitting = false;
        return false;
      }
      try {
        let usdtAmount = this.amount * this.user.dogePrice;
        const min = this.user.min - this.user.depositAmount;
        const max = this.user.max - this.user.depositAmount;
        if (min > 0 && usdtAmount < min) {
          usdtAmount = min;
        }
        if (usdtAmount > max) {
          usdtAmount = max;
        }
        let buyTxHash;
        if (!this.user.positionOpened) {
          buyTxHash = await common_sendTransaction({
            to: config["a" /* default */].MartinDepositAddress,
            gas: 640000,
            data: ethereum["d" /* martinDepositInterface */].encodeFunctionData('open', [bignumber["a" /* BigNumber */].from(Math.round(usdtAmount).toString()).toHexString(), this.type, this.invitee])
          });
        } else {
          buyTxHash = await common_sendTransaction({
            to: config["a" /* default */].MartinDepositAddress,
            gas: 640000,
            data: ethereum["d" /* martinDepositInterface */].encodeFunctionData('deposit', [bignumber["a" /* BigNumber */].from(Math.round(usdtAmount).toString()).toHexString()])
          });
        }
        this.showPending('Pending', {
          tx: buyTxHash
        });
        const buyTx = await ethereum["e" /* provider */].waitForTransaction(buyTxHash);
        if (buyTx.status === 1) {
          this.showSuccess('Success', {
            tx: buyTxHash
          });
          this.amount = '';
          this.$emit('change-step', 3);
          await this.$store.dispatch('getPosition');
          this.$store.dispatch('getWithdrawable');
          this.$store.dispatch('getBalances');
        } else {
          this.showError('Faild', {
            tx: buyTxHash
          });
        }
      } finally {
        this.submitting = false;
      }
    },
    onCancel() {
      if (this.user.positionOpened) {
        this.$emit('change-step', 3);
      } else {
        this.$emit('change-step', 1);
      }
    }
  }
}));
// CONCATENATED MODULE: ./src/views/Home/components/Subscribe.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Subscribevue_type_script_lang_js_ = (Subscribevue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/Subscribe.vue?vue&type=style&index=0&id=f04610f4&prod&lang=scss&scoped=true&
var Subscribevue_type_style_index_0_id_f04610f4_prod_lang_scss_scoped_true_ = __webpack_require__("58bc");

// CONCATENATED MODULE: ./src/views/Home/components/Subscribe.vue






/* normalize component */

var Subscribe_component = Object(componentNormalizer["a" /* default */])(
  components_Subscribevue_type_script_lang_js_,
  Subscribevue_type_template_id_f04610f4_scoped_true_render,
  Subscribevue_type_template_id_f04610f4_scoped_true_staticRenderFns,
  false,
  null,
  "f04610f4",
  null
  
)

/* harmony default export */ var Subscribe = (Subscribe_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/MyAssets.vue?vue&type=template&id=ad6dd15a&scoped=true&
var MyAssetsvue_type_template_id_ad6dd15a_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"my-assets"},[_c('h3',[_vm._v("My Assets")]),_c('div',{staticClass:"assets-wrapper"},[_c('div',{staticClass:"total"},[_vm._v(" USDT: "+_vm._s(Math.round(_vm.user.dogeBalance / (Math.pow( 10, _vm.user.dogeDecimals ))))+" ")]),_c('div',{staticClass:"card"},[_c('div',{staticClass:"card-top"},[_c('span',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Regular Interest' : 'Daily Interest'))]),_c('span',[_vm._v(" "+_vm._s(_vm.user.period === 0 ? 30 : 365)+" days")])]),_c('div',{staticClass:"card-middle"},[_c('span',[_vm._v("APR: ")]),_c('span',[_vm._v(" "+_vm._s(_vm.user.period === 0 ? '72.00%+' : '120.00%+'))])]),_c('div',{staticClass:"card-bottom"},[_c('span',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Pay interest only when due' : 'Receive interest the next day'))])])])]),_c('h3',[_vm._v("My Subscription")]),_c('div',{staticClass:"table-wrapper"},[_c('table',{staticClass:"reward-table"},[_c('thead',{staticClass:"table-head"},[_c('tr',[_c('th',[_vm._v("Product")]),_c('th',[_vm._v("Value")]),(_vm.user.period === 1)?_c('th',[_vm._v("Available")]):_vm._e(),_c('th',[_vm._v("Time")])])]),_c('tbody',[_c('tr',{staticClass:"table-row"},[_c('td',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Regular Interest' : 'Daily Interest'))]),(_vm.user.period === 0)?_c('td',[_vm._v(" $ "+_vm._s(_vm._f("toFixed")(_vm.user.withdrawable / Math.pow( 10, _vm.user.usdDecimals )))+" ")]):_vm._e(),(_vm.user.period === 1)?_c('td',[_vm._v(" $ "+_vm._s(_vm._f("toFixed")(_vm.user.amount365 / Math.pow( 10, _vm.user.usdDecimals )))+" ")]):_vm._e(),(_vm.user.period === 1)?_c('td',[_vm._v(" $ "+_vm._s(_vm._f("toFixed")(_vm.user.withdrawable / Math.pow( 10, _vm.user.usdDecimals )))+" ")]):_vm._e(),_c('td',[_vm._v(_vm._s(_vm._f("formatTime")(_vm.time,'yyyy-MM-DD')))])])])])]),_c('b-row',{attrs:{"align-h":"center"}},[_c('div',{staticClass:"btn-wrapper"},[_c('b-button',{staticClass:"subscribe-btn",attrs:{"variant":"primary"},on:{"click":_vm.onSubscribe}},[_vm._v("Subscribe")]),_c('b-button',{staticClass:"redeem-btn",attrs:{"variant":"primary"},on:{"click":_vm.onRedeem}},[_vm._v("Redeem")]),(_vm.user.period === 1)?_c('b-button',{staticClass:"redelivery-btn",attrs:{"variant":"primary","disabled":_vm.user.withdrawable === 0},on:{"click":_vm.onReinvest}},[_vm._v("Reinvest")]):_vm._e()],1)])],1)}
var MyAssetsvue_type_template_id_ad6dd15a_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/MyAssets.vue?vue&type=template&id=ad6dd15a&scoped=true&

// EXTERNAL MODULE: ./src/api/common.js
var common = __webpack_require__("2934");

// EXTERNAL MODULE: ./node_modules/@openzeppelin/merkle-tree/dist/index.js
var dist = __webpack_require__("101e");

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/MyAssets.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//








/* harmony default export */ var MyAssetsvue_type_script_lang_js_ = ({
  data() {
    return {
      list: [{
        type: '222',
        claimable: '1'
      }, {
        type: '222',
        claimable: '1'
      }]
    };
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user']),
    time() {
      if (this.user.events.length > 0) {
        return this.user.events[0].time * 1000;
      }
      return '';
    }
  },
  // async mounted() {
  //   const tree = await getTree();
  //   console.log(tree)
  // },
  methods: {
    onSubscribe() {
      this.$emit('change-step', 2);
    },
    onRedeem() {
      this.$emit('change-step', 4);
    },
    async onReinvest() {
      this.$emit('change-step', 4, 'reinvest');
      // const { tokenId } = this.$route.query;
      // if (!this.user.address) {
      //   this.showError('Please connect metamask');
      //   return false;
      // }

      // if (amount < this.min) {
      //   this.showError(`The minimum claim is ${this.min} DOGE`);
      //   return;
      // }

      // if (amount > this.max) {
      //   this.showError(`The maximum claim is ${this.min} DOGE`);
      //   return;
      // }
    }
  }
});
// CONCATENATED MODULE: ./src/views/Home/components/MyAssets.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_MyAssetsvue_type_script_lang_js_ = (MyAssetsvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/MyAssets.vue?vue&type=style&index=0&id=ad6dd15a&prod&lang=scss&scoped=true&
var MyAssetsvue_type_style_index_0_id_ad6dd15a_prod_lang_scss_scoped_true_ = __webpack_require__("0807");

// CONCATENATED MODULE: ./src/views/Home/components/MyAssets.vue






/* normalize component */

var MyAssets_component = Object(componentNormalizer["a" /* default */])(
  components_MyAssetsvue_type_script_lang_js_,
  MyAssetsvue_type_template_id_ad6dd15a_scoped_true_render,
  MyAssetsvue_type_template_id_ad6dd15a_scoped_true_staticRenderFns,
  false,
  null,
  "ad6dd15a",
  null
  
)

/* harmony default export */ var MyAssets = (MyAssets_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Claim.vue?vue&type=template&id=6f72bcac&scoped=true&
var Claimvue_type_template_id_6f72bcac_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"subscribe"},[_c('b-row',{attrs:{"align-v":"start"}},[_c('b-col',{staticClass:"left-section",attrs:{"lg":"6"}},[_c('div',{staticClass:"content-row row-product"},[_c('div',{staticClass:"label label-short"},[_vm._v("Product：")]),_c('div',{staticClass:"content"},[_c('span',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Regular Interest' : 'Daily Interest'))])])]),_c('div',{staticClass:"content-row row-product"},[_c('div',{staticClass:"label label-short"},[_vm._v("APR: ")]),_c('div',{staticClass:"content"},[_c('span',[_c('em',[_vm._v(_vm._s(_vm.user.period === 0 ? '72.00%+' : '120.00%+'))])])])]),_c('div',{staticClass:"content-row row-amount"},[_c('div',{staticClass:"label label-short"},[_vm._v("Amount：")]),_c('div',{staticClass:"content"},[_c('div',{staticClass:"content-left"},[_c('input',{directives:[{name:"model",rawName:"v-model.number",value:(_vm.amount),expression:"amount",modifiers:{"number":true}}],attrs:{"placeholder":("Available:" + _vm.claimable),"type":"number"},domProps:{"value":(_vm.amount)},on:{"input":[function($event){if($event.target.composing){ return; }_vm.amount=_vm._n($event.target.value)},_vm.onInput],"blur":function($event){return _vm.$forceUpdate()}}})]),_c('div',{staticClass:"content-right"},[_c('span',{staticClass:"max-btn",on:{"click":function($event){_vm.amount = _vm.max}}},[_vm._v("MAX")])])])]),_c('div',{staticClass:"content-row row-tip"},[_c('div',{staticClass:"content"},[_vm._v(" = $ "+_vm._s(_vm._f("toFixed")((_vm.amount * _vm.user.dogePrice / Math.pow( 10, _vm.user.dogePriceDecimals )),2))+" ")])])]),_c('b-col',{staticClass:"right-section",attrs:{"lg":"6"}},[_c('div',{staticClass:"content-row row-operating"},[_c('div',{staticClass:"label"},[_vm._v("Interest payment：")]),_c('div',{staticClass:"content"},[_c('div',[_c('span',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Pay interest only when due' : 'Receive interest the next day'))]),_c('br'),_vm._v(" No interest for redemption before maturity ")])])]),_c('div',{staticClass:"content-row"},[_c('div',{staticClass:"label"}),_c('div',{staticClass:"content"},[_c('div',{staticClass:"timeline"},[_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("Subscription date")]),_c('div',{staticClass:"time"},[_vm._v(" "+_vm._s(_vm.subscriptionDate))])]),_c('span',{staticClass:"line"}),_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("Accrual Start Date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.valueDate)+" 08:00:00")])]),_c('span',{staticClass:"line"}),_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("First Distribution Date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.interestDate)+" 08:00:00")])])])])])])],1),_c('b-row',{attrs:{"align-h":"center"}},[_c('div',{staticClass:"btn-wrapper"},[(_vm.user.period === 0)?_c('div',{staticClass:"tip"},[_vm._v("Tips:0.5% handling fee will be deducted for redemption.")]):_vm._e(),(_vm.user.period === 1)?_c('div',{staticClass:"tip"},[_vm._v("Tips:0.5% handling fee will be deducted for redemption, and 10% of the funds will be automatically reinvested.")]):_vm._e(),_c('b-button',{staticClass:"subscribe-btn",attrs:{"variant":"primary","disabled":_vm.submitting || _vm.user.withdrawable === 0 || !_vm.amount},on:{"click":_vm.onClaim}},[_vm._v(" Redeem "),(_vm.submitting)?_c('b-icon',{attrs:{"icon":"arrow-repeat","rotate":"45","animation":"spin"}}):_vm._e()],1),_c('b-button',{staticClass:"cancel-btn",on:{"click":_vm.onCancel}},[_vm._v("Cancel")])],1)])],1)}
var Claimvue_type_template_id_6f72bcac_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/Claim.vue?vue&type=template&id=6f72bcac&scoped=true&

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Claim.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//










/* harmony default export */ var Claimvue_type_script_lang_js_ = (Object(vue_composition_api["b" /* defineComponent */])({
  props: {
    type: {
      type: Number
    }
  },
  data() {
    return {
      invitee: config["a" /* default */].addressZero,
      submitting: false,
      amount: ''
    };
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user']),
    time() {
      if (this.user.events.length > 0) {
        return this.user.events[0].time * 1000;
      }
      return '';
    },
    claimable() {
      return Math.floor(this.user.withdrawable / this.user.dogePrice);
    },
    min() {
      return 1;
    },
    max() {
      return this.claimable;
    },
    subscriptionDate() {
      return moment_default()(this.time).format('yyyy-MM-DD HH:mm:ss');
    },
    valueDate() {
      return moment_default()(this.time).add(1, 'day').format('yyyy-MM-DD');
    },
    interestDate() {
      if (this.user.period === 0) {
        return moment_default()(this.time).add(30, 'day').format('yyyy-MM-DD');
      }
      if (this.user.period === 1) {
        return moment_default()(this.time).add(365, 'day').format('yyyy-MM-DD');
      }
    }
  },
  methods: {
    onInput(event) {
      let {
        value
      } = event.target;
      value = value.replace(/[^\d]/g, ''); // 只保留数字
      this.amount = parseInt(value, 10); // 转成数字类型
      if (this.amount > this.max) {
        this.amount = this.max;
      }
    },
    async onClaim() {
      // const { tokenId } = this.$route.query;
      const {
        amount
      } = this;
      if (amount < this.min) {
        this.showError(`The minimum claim is ${this.min} USDT`);
        return;
      }
      if (amount > this.max) {
        this.showError(`The maximum claim is ${this.min} USDT`);
        return;
      }
      if (!this.user.address) {
        this.showError('Please connect metamask');
        return false;
      }
      if (!this.user.jsonAmount) {
        this.showError('Withdrawal is only possible after 24 hours');
        return false;
      }
      this.submitting = true;
      try {
        const usdtAmount = this.amount * this.user.dogePrice;
        const content = await Object(common["b" /* getTree */])();
        const tree = dist["StandardMerkleTree"].load(content);
        let proof = '';
        // eslint-disable-next-line no-restricted-syntax
        for (const [i, v] of tree.entries()) {
          if (v[0].toLowerCase() === this.user.address.toLowerCase()) {
            proof = tree.getProof(i);
          }
        }
        const buyTxHash = await common_sendTransaction({
          to: config["a" /* default */].MartinDepositAddress,
          gas: 640000,
          data: ethereum["d" /* martinDepositInterface */].encodeFunctionData('withdraw', [proof, this.user.jsonAmount, bignumber["a" /* BigNumber */].from(Math.round(usdtAmount).toString()).toHexString()])
        });
        this.showPending('Pending', {
          tx: buyTxHash
        });
        const buyTx = await ethereum["e" /* provider */].waitForTransaction(buyTxHash);
        if (buyTx.status === 1) {
          this.showSuccess('Succeeded', {
            tx: buyTxHash
          });
          this.amount = '';
          this.$store.dispatch('getPosition');
          this.$store.dispatch('getWithdrawable');
          this.$store.dispatch('getBalances');
        } else {
          this.showError('Failed', {
            tx: buyTxHash
          });
        }
      } catch (error) {
        console.error(error);
      }
      this.submitting = false;
    },
    onCancel() {
      if (this.user.positionOpened) {
        this.$emit('change-step', 3);
      } else {
        this.$emit('change-step', 1);
      }
    }
  }
}));
// CONCATENATED MODULE: ./src/views/Home/components/Claim.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Claimvue_type_script_lang_js_ = (Claimvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/Claim.vue?vue&type=style&index=0&id=6f72bcac&prod&lang=scss&scoped=true&
var Claimvue_type_style_index_0_id_6f72bcac_prod_lang_scss_scoped_true_ = __webpack_require__("60a3");

// CONCATENATED MODULE: ./src/views/Home/components/Claim.vue






/* normalize component */

var Claim_component = Object(componentNormalizer["a" /* default */])(
  components_Claimvue_type_script_lang_js_,
  Claimvue_type_template_id_6f72bcac_scoped_true_render,
  Claimvue_type_template_id_6f72bcac_scoped_true_staticRenderFns,
  false,
  null,
  "6f72bcac",
  null
  
)

/* harmony default export */ var Claim = (Claim_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Reinvest.vue?vue&type=template&id=478f9844&scoped=true&
var Reinvestvue_type_template_id_478f9844_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"subscribe"},[_c('b-row',{attrs:{"align-v":"start"}},[_c('b-col',{staticClass:"left-section",attrs:{"lg":"6"}},[_c('div',{staticClass:"content-row row-product"},[_c('div',{staticClass:"label label-short"},[_vm._v("Product：")]),_c('div',{staticClass:"content"},[_c('span',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Regular Interest' : 'Daily Interest'))])])]),_c('div',{staticClass:"content-row row-product"},[_c('div',{staticClass:"label label-short"},[_vm._v("APR: ")]),_c('div',{staticClass:"content"},[_c('span',[_c('em',[_vm._v(_vm._s(_vm.user.period === 0 ? '72.00%+' : '120.00%+'))])])])]),_c('div',{staticClass:"content-row row-amount"},[_c('div',{staticClass:"label label-short"},[_vm._v("Amount：")]),_c('div',{staticClass:"content"},[_c('div',{staticClass:"content-left"},[_c('input',{directives:[{name:"model",rawName:"v-model.number",value:(_vm.amount),expression:"amount",modifiers:{"number":true}}],attrs:{"placeholder":("Available:" + _vm.claimable),"type":"number"},domProps:{"value":(_vm.amount)},on:{"input":[function($event){if($event.target.composing){ return; }_vm.amount=_vm._n($event.target.value)},_vm.onInput],"blur":function($event){return _vm.$forceUpdate()}}})]),_c('div',{staticClass:"content-right"},[_c('span',{staticClass:"max-btn",on:{"click":function($event){_vm.amount = _vm.max}}},[_vm._v("MAX")])])])]),_c('div',{staticClass:"content-row row-tip"},[_c('div',{staticClass:"content"},[_vm._v(" = $ "+_vm._s(_vm._f("toFixed")((_vm.amount * _vm.user.dogePrice / Math.pow( 10, _vm.user.dogePriceDecimals )),2))+" ")])])]),_c('b-col',{staticClass:"right-section",attrs:{"lg":"6"}},[_c('div',{staticClass:"content-row row-operating"},[_c('div',{staticClass:"label"},[_vm._v("Interest payment：")]),_c('div',{staticClass:"content"},[_c('div',[_c('span',[_vm._v(_vm._s(_vm.user.period === 0 ? 'Pay interest only when due' : 'Receive interest the next day'))]),_c('br'),_vm._v(" No interest for redemption before maturity ")])])]),_c('div',{staticClass:"content-row"},[_c('div',{staticClass:"label"}),_c('div',{staticClass:"content"},[_c('div',{staticClass:"timeline"},[_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("Subscription date")]),_c('div',{staticClass:"time"},[_vm._v(" "+_vm._s(_vm.subscriptionDate))])]),_c('span',{staticClass:"line"}),_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("Accrual Start Date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.valueDate)+" 08:00:00")])]),_c('span',{staticClass:"line"}),_c('div',{staticClass:"timeline-item"},[_c('div',{staticClass:"discribe"},[_vm._v("First Distribution Date")]),_c('div',{staticClass:"time"},[_vm._v(_vm._s(_vm.interestDate)+" 08:00:00")])])])])])])],1),_c('b-row',{attrs:{"align-h":"center"}},[_c('div',{staticClass:"btn-wrapper"},[_c('b-button',{staticClass:"subscribe-btn",attrs:{"variant":"primary","disabled":_vm.submitting || _vm.user.withdrawable === 0 || !_vm.amount},on:{"click":_vm.onReinvest}},[_vm._v(" Reinvest "),(_vm.submitting)?_c('b-icon',{attrs:{"icon":"arrow-repeat","rotate":"45","animation":"spin"}}):_vm._e()],1)],1)])],1)}
var Reinvestvue_type_template_id_478f9844_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/Reinvest.vue?vue&type=template&id=478f9844&scoped=true&

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Reinvest.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//










/* harmony default export */ var Reinvestvue_type_script_lang_js_ = (Object(vue_composition_api["b" /* defineComponent */])({
  props: {
    type: {
      type: Number
    }
  },
  data() {
    return {
      invitee: config["a" /* default */].addressZero,
      submitting: false,
      amount: '',
      time: Date.now()
    };
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user']),
    claimable() {
      return Math.floor(this.user.withdrawable / this.user.dogePrice);
    },
    min() {
      return 1;
    },
    max() {
      return this.claimable;
    },
    subscriptionDate() {
      return moment_default()(this.time).format('yyyy-MM-DD HH:mm:ss');
    },
    valueDate() {
      return moment_default()(this.time).add(1, 'day').format('yyyy-MM-DD');
    },
    interestDate() {
      if (this.user.period === 0) {
        return moment_default()(this.time).add(30, 'day').format('yyyy-MM-DD');
      }
      if (this.user.period === 1) {
        return moment_default()(this.time).add(365, 'day').format('yyyy-MM-DD');
      }
    }
  },
  methods: {
    onInput(event) {
      let {
        value
      } = event.target;
      value = value.replace(/[^\d]/g, ''); // 只保留数字
      this.amount = parseInt(value, 10); // 转成数字类型
      if (this.amount > this.max) {
        this.amount = this.max;
      }
    },
    async onReinvest() {
      // const { tokenId } = this.$route.query;
      if (!this.user.address) {
        this.showError('Please connect metamask');
        return false;
      }
      if (this.amount < this.min) {
        this.showError(`The minimum claim is ${this.min} USDT`);
        return;
      }
      if (this.amount > this.max) {
        this.showError(`The maximum claim is ${this.min} USDT`);
        return;
      }
      // const amount = this.user.withdrawable;

      this.submitting = true;
      try {
        // const usdtAmount = amount * this.user.dogePrice;

        const content = await Object(common["b" /* getTree */])();
        const tree = dist["StandardMerkleTree"].load(content);
        let proof = '';
        // eslint-disable-next-line no-restricted-syntax
        for (const [i, v] of tree.entries()) {
          if (v[0].toLowerCase() === this.user.address.toLowerCase()) {
            proof = tree.getProof(i);
          }
        }
        if (!proof) {
          this.showError('There is no proof for your address');
          return false;
        }
        const usdtAmount = this.amount * this.user.dogePrice;

        // console.log(this.amount.toString());
        // console.log(usdtAmount.toString());
        const buyTxHash = await common_sendTransaction({
          to: config["a" /* default */].MartinDepositAddress,
          gas: 640000,
          data: ethereum["d" /* martinDepositInterface */].encodeFunctionData('reinvest', [proof, this.user.jsonAmount, bignumber["a" /* BigNumber */].from(usdtAmount.toString()).toHexString()])
        });
        this.showPending('Pending', {
          tx: buyTxHash
        });
        const buyTx = await ethereum["e" /* provider */].waitForTransaction(buyTxHash);
        if (buyTx.status === 1) {
          this.showSuccess('Succeeded', {
            tx: buyTxHash
          });
          this.amount = '';
          this.$store.dispatch('getPosition');
          this.$store.dispatch('getWithdrawable');
          this.$store.dispatch('getBalances');
        } else {
          this.showError('Failed', {
            tx: buyTxHash
          });
        }
      } catch (error) {
        console.error(error);
      }
      this.submitting = false;
    },
    onCancel() {
      if (this.user.positionOpened) {
        this.$emit('change-step', 3);
      } else {
        this.$emit('change-step', 1);
      }
    }
  }
}));
// CONCATENATED MODULE: ./src/views/Home/components/Reinvest.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Reinvestvue_type_script_lang_js_ = (Reinvestvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/Reinvest.vue?vue&type=style&index=0&id=478f9844&prod&lang=scss&scoped=true&
var Reinvestvue_type_style_index_0_id_478f9844_prod_lang_scss_scoped_true_ = __webpack_require__("f3d7");

// CONCATENATED MODULE: ./src/views/Home/components/Reinvest.vue






/* normalize component */

var Reinvest_component = Object(componentNormalizer["a" /* default */])(
  components_Reinvestvue_type_script_lang_js_,
  Reinvestvue_type_template_id_478f9844_scoped_true_render,
  Reinvestvue_type_template_id_478f9844_scoped_true_staticRenderFns,
  false,
  null,
  "478f9844",
  null
  
)

/* harmony default export */ var Reinvest = (Reinvest_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Marshmallow.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//








/* harmony default export */ var Marshmallowvue_type_script_lang_js_ = ({
  components: {
    SubscribeSelect: SubscribeSelect,
    Subscribe: Subscribe,
    MyAssets: MyAssets,
    Claim: Claim,
    Reinvest: Reinvest
  },
  mixins: [toastMixin["a" /* default */]],
  data() {
    return {
      step: 1,
      type: 0,
      slideType: 'claim' // 'reinvest'
    };
  },

  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user'])
  },
  watch: {
    'user.positionOpened': function (val) {
      if (val) {
        this.step = 3;
      }
    },
    'user.period': function (val) {
      if (val) {
        this.type = val;
      }
    }
  },
  created() {
    // this.getMines();
  },
  methods: {
    ...Object(vuex_esm["b" /* mapActions */])(['showComingSoon']),
    unlock() {
      this.$store.dispatch('unlockByMetaMask');
    },
    onNextOne(type) {
      this.type = type;
      this.step = 2;
    },
    onNextTwo() {
      // this.step = 3;
    },
    onPrevTwo() {
      this.step = 1;
    },
    onChangeStep(val, slideType = 'claim') {
      this.step = val;
      this.slideType = slideType;
    },
    changeInviteCard(id) {
      this.active = id;
    },
    subscribe() {
      // console.log('xxxx');
      this.showError('123123', {
        tx: '123'
      });
    }
  }
});
// CONCATENATED MODULE: ./src/views/Home/components/Marshmallow.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Marshmallowvue_type_script_lang_js_ = (Marshmallowvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/Marshmallow.vue?vue&type=style&index=0&id=01415f38&prod&lang=scss&scoped=true&
var Marshmallowvue_type_style_index_0_id_01415f38_prod_lang_scss_scoped_true_ = __webpack_require__("1e5d");

// CONCATENATED MODULE: ./src/views/Home/components/Marshmallow.vue






/* normalize component */

var Marshmallow_component = Object(componentNormalizer["a" /* default */])(
  components_Marshmallowvue_type_script_lang_js_,
  Marshmallowvue_type_template_id_01415f38_scoped_true_render,
  Marshmallowvue_type_template_id_01415f38_scoped_true_staticRenderFns,
  false,
  null,
  "01415f38",
  null
  
)

/* harmony default export */ var Marshmallow = (Marshmallow_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/CommonProblem.vue?vue&type=template&id=00cff8cd&scoped=true&
var CommonProblemvue_type_template_id_00cff8cd_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"problems",attrs:{"id":"FAQ"}},[_c('b-container',{attrs:{"fluid":"lg"}},[_c('h2',[_vm._v("FAQ")]),_c('b-row',{staticClass:"list"},_vm._l((_vm.list),function(item,idx){return _c('div',{key:item.title,staticClass:"list-item",class:{ active: idx === _vm.active },on:{"click":function($event){return _vm.onClick(idx)}}},[_c('div',[_c('span',{staticClass:"num-wrapper"},[_vm._v(" "+_vm._s(idx + 1)+" ")]),_c('span',{staticClass:"item-title"},[_vm._v(" "+_vm._s(item.title)+" ")])]),(idx === _vm.active)?_c('div',{staticClass:"item-content",domProps:{"innerHTML":_vm._s(item.desc)}}):_vm._e(),_c('span',{staticClass:"arrow"},[_c('img',{staticClass:"arrow-img",attrs:{"src":__webpack_require__("c4b3"),"alt":""}})])])}),0)],1)],1)}
var CommonProblemvue_type_template_id_00cff8cd_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/CommonProblem.vue?vue&type=template&id=00cff8cd&scoped=true&

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/CommonProblem.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//


/* harmony default export */ var CommonProblemvue_type_script_lang_js_ = ({
  components: {},
  data() {
    return {
      active: '',
      list: [{
        title: 'How to be considered a successful referral?',
        desc: "To be considered a successful referral, the referee must link their wallet for the first time through the referrer's link and successfully subscribe to a transaction."
      }, {
        title: 'How to earn income through Regular Interest？',
        desc: `To earn income through Regular Interest, one can subscribe to Regular Interest products for a 30-day period and receive interest only when it is due. No interest will be given for redemption before maturity. It's important to note that a 0.5% handling fee will be charged for redemption, regardless of whether it's due or not.`
      }, {
        title: 'How to earn income through Daily Interest? ',
        desc: `To earn income through Daily Interest, one can subscribe to Daily Interest products for a cycle of 365 days. After successful subscription, interest will be received the next day, and it will stop immediately after redemption. It's important to note that a 0.5% handling fee will be charged for redemption, regardless of whether it's expired or not. Additionally, 10% of the redemption funds will be automatically reinvested.`
      }, {
        title: 'What is the burn rule?',
        desc: `The referrer's rebate depends on the minimum number of subscriptions between the referrer and the referee. For example, if Bob recommends Alice, and Alice subscribes for 20,000 USDT while Bob subscribes for 10,000 USDT, then the rebate for Bob as the referrer will be calculated at 10,000 USDT because Bob has the least number of subscriptions among Bob and Alice.`
      }, {
        title: 'What is a global dividend and how do I qualify for a dividend?',
        desc: `A global dividend is a 0.5% income earned by level 5 referrers from all of their referees' income. Here, the referee's income refers to the portion of the referee's own income from referrals. To qualify for a dividend, one must upgrade to level 5 referrer and maintain a current subscription amount of no less than $20,000.`
      }, {
        title: 'How to upgrade to the next level referees？',
        desc: `Advance to the next level by referring at least 2 direct referees.`
      }, {
        title: 'What is the subscription limit? ',
        desc: 'The minimum subscription limit is $1000 worth of USDT, while the maximum amount of USDT that can be subscribed is $20000.'
      }]
    };
  },
  computed: {},
  created() {
    // this.getMines();
  },
  methods: {
    onClick(val) {
      if (this.active === val) {
        this.active = '';
      } else {
        this.active = val;
      }
    }
  }
});
// CONCATENATED MODULE: ./src/views/Home/components/CommonProblem.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_CommonProblemvue_type_script_lang_js_ = (CommonProblemvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/CommonProblem.vue?vue&type=style&index=0&id=00cff8cd&prod&lang=scss&scoped=true&
var CommonProblemvue_type_style_index_0_id_00cff8cd_prod_lang_scss_scoped_true_ = __webpack_require__("bfa7");

// CONCATENATED MODULE: ./src/views/Home/components/CommonProblem.vue






/* normalize component */

var CommonProblem_component = Object(componentNormalizer["a" /* default */])(
  components_CommonProblemvue_type_script_lang_js_,
  CommonProblemvue_type_template_id_00cff8cd_scoped_true_render,
  CommonProblemvue_type_template_id_00cff8cd_scoped_true_staticRenderFns,
  false,
  null,
  "00cff8cd",
  null
  
)

/* harmony default export */ var CommonProblem = (CommonProblem_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Recommend.vue?vue&type=template&id=164d6c28&scoped=true&
var Recommendvue_type_template_id_164d6c28_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"recommend"},[_c('b-container',{attrs:{"fluid":"lg"}},[_c('h2',[_vm._v("My Referrals")]),_c('b-row',{staticClass:"recommend-container",attrs:{"align-h":"between"}},[_c('b-col',{staticClass:"left",attrs:{"md":"4","order":"2","order-md":"1"}},[_c('img',{staticClass:"dog-bg",attrs:{"src":__webpack_require__("912b"),"alt":""}}),_c('img',{staticClass:"dog-img",attrs:{"src":__webpack_require__("fb6e"),"alt":""}})]),_c('b-col',{staticClass:"right",attrs:{"md":"7","order":"1","order-md":"2"}},[_c('div',{staticClass:"tip"},[_vm._v(" Whether to qualify for global dividends "),_c('img',{staticClass:"question",attrs:{"id":"tooltip-target-007","src":__webpack_require__("905f"),"alt":""}}),_c('em',[_vm._v(" "+_vm._s(_vm.user.inviterGrade >= 4 ? 'Yes' : 'No'))]),_c('b-tooltip',{attrs:{"target":"tooltip-target-007","triggers":"hover"}},[_vm._v(" Become a level 5 recommender to get global dividends ")])],1),_c('div',{staticClass:"table-wrapper"},[_c('table',[_c('thead',{staticClass:"table-head"},[_c('tr',[_c('th',[_vm._v("Referee's address")]),_c('th',[_vm._v("Level")]),_c('th',[_vm._v("Referrer's address")]),_c('th',[_vm._v("Date")])])]),_c('tbody',[(_vm.currentList.length)?_vm._l((_vm.currentList),function(item){return _c('tr',{staticClass:"table-row"},[_c('td',[_vm._v(_vm._s(_vm._f("ellipsis")(item.addr)))]),_c('td',[_vm._v(_vm._s(item.level + 1))]),_c('td',[_vm._v(_vm._s(_vm._f("ellipsis")(item.inviter)))]),_c('td',[_vm._v(_vm._s(_vm._f("formatTime")(item.time * 1000,'yyyy-MM-DD HH:mm:ss')))])])}):_c('tr',{staticClass:"table-row empty-row"},[_c('td',{attrs:{"colspan":"4"}},[_vm._v("No Data")])])],2)])]),_c('Pagination',{attrs:{"page-size":_vm.pageSize,"page":_vm.page,"total":_vm.user.invitees.length},on:{"change":_vm.onPageChange}})],1)],1)],1)],1)}
var Recommendvue_type_template_id_164d6c28_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/Recommend.vue?vue&type=template&id=164d6c28&scoped=true&

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/components/Pagination.vue?vue&type=template&id=7b09cf62&scoped=true&
var Paginationvue_type_template_id_7b09cf62_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"pagination"},[_c('ul',[_c('li',{staticClass:"left-btn",on:{"click":_vm.onPrev}},[_vm._v("<")]),_vm._l((_vm.pageList),function(item){return _c('li',{key:item,class:{
        active: item === _vm.page
       },on:{"click":function () {
        if (item !== '...') {
          _vm.onChange(item)
        }
       }}},[_vm._v(_vm._s(item))])}),_c('li',{staticClass:"right-btn",on:{"click":_vm.onNext}},[_vm._v(">")])],2)])}
var Paginationvue_type_template_id_7b09cf62_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/components/Pagination.vue?vue&type=template&id=7b09cf62&scoped=true&

// EXTERNAL MODULE: ./src/common/generatePagination.js
var generatePagination = __webpack_require__("715f");
var generatePagination_default = /*#__PURE__*/__webpack_require__.n(generatePagination);

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/components/Pagination.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//



/* harmony default export */ var Paginationvue_type_script_lang_js_ = (Object(vue_composition_api["b" /* defineComponent */])({
  props: {
    page: {
      type: Number,
      default: 1
    },
    pageSize: {
      type: Number,
      default: 1
    },
    total: {
      type: Number,
      default: 10
    }
  },
  setup(props, context) {
    const onPrev = () => {
      if (props.page > 1) {
        context.emit('change', props.page - 1);
      }
    };
    const onNext = () => {
      if (props.page < Math.ceil(props.total / props.pageSize)) {
        context.emit('change', props.page + 1);
      }
    };
    const onChange = val => {
      context.emit('change', val);
    };

    // console.log(props.total, props.pageSize)
    // console.log({
    //   showPageCount: 10,
    //   currentPage: props.page,
    //   pageCount: Math.ceil(props.total / props.pageSize),
    // });
    const pageList = generatePagination_default()({
      showPageCount: 10,
      currentPage: props.page,
      pageCount: Math.ceil(props.total / props.pageSize) || 1
    });
    return {
      onPrev,
      onNext,
      onChange,
      pageList
    };
  }
}));
// CONCATENATED MODULE: ./src/components/Pagination.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Paginationvue_type_script_lang_js_ = (Paginationvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/components/Pagination.vue?vue&type=style&index=0&id=7b09cf62&prod&lang=scss&scoped=true&
var Paginationvue_type_style_index_0_id_7b09cf62_prod_lang_scss_scoped_true_ = __webpack_require__("9f4d");

// CONCATENATED MODULE: ./src/components/Pagination.vue






/* normalize component */

var Pagination_component = Object(componentNormalizer["a" /* default */])(
  components_Paginationvue_type_script_lang_js_,
  Paginationvue_type_template_id_7b09cf62_scoped_true_render,
  Paginationvue_type_template_id_7b09cf62_scoped_true_staticRenderFns,
  false,
  null,
  "7b09cf62",
  null
  
)

/* harmony default export */ var Pagination = (Pagination_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Recommend.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//




// import {
//   martinDepositInterface, provider,
// } from '@/eth/ethereum';

/* harmony default export */ var Recommendvue_type_script_lang_js_ = ({
  components: {
    Pagination: Pagination
  },
  filters: {
    ellipsis(address) {
      return address.replace(/^(.{6}).*(.{4})$/, '$1...$2');
    }
  },
  data() {
    return {
      page: 1,
      total: 10,
      pageSize: 10,
      active: ''
    };
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user']),
    list() {
      return this.user.invitees;
    },
    currentList() {
      return this.user.invitees.slice((this.page - 1) * this.pageSize, this.page * this.pageSize);
    }
  },
  created() {
    this.$store.dispatch('getInvitees');
  },
  methods: {
    onClick(val) {
      if (this.active === val) {
        this.active = '';
      } else {
        this.active = val;
      }
    },
    onPageChange(val) {
      this.page = val;
    }
  }
});
// CONCATENATED MODULE: ./src/views/Home/components/Recommend.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Recommendvue_type_script_lang_js_ = (Recommendvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/Recommend.vue?vue&type=style&index=0&id=164d6c28&prod&lang=scss&scoped=true&
var Recommendvue_type_style_index_0_id_164d6c28_prod_lang_scss_scoped_true_ = __webpack_require__("807e");

// CONCATENATED MODULE: ./src/views/Home/components/Recommend.vue






/* normalize component */

var Recommend_component = Object(componentNormalizer["a" /* default */])(
  components_Recommendvue_type_script_lang_js_,
  Recommendvue_type_template_id_164d6c28_scoped_true_render,
  Recommendvue_type_template_id_164d6c28_scoped_true_staticRenderFns,
  false,
  null,
  "164d6c28",
  null
  
)

/* harmony default export */ var Recommend = (Recommend_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js?{"cacheDirectory":"node_modules/.cache/vue-loader","cacheIdentifier":"694df186-vue-loader-template"}!./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Invitation.vue?vue&type=template&id=597e9484&scoped=true&
var Invitationvue_type_template_id_597e9484_scoped_true_render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{staticClass:"invitation",attrs:{"id":"InvitationRebate"}},[_c('b-container',{attrs:{"fluid":"lg"}},[_c('h2',[_vm._v("Referral & Rebate")]),_c('div',{staticClass:"sub-title"},[_vm._v("Referral friends, earn more income, and qualify for global dividends")]),_c('div',{staticClass:"rules-container"},[_c('div',{staticClass:"rules-title"},[_vm._v(" Rebate Rules: "),_c('em',[_vm._v("(Rebates can be claimed regularly)")])]),_c('div',{staticClass:"rules-list"},[_c('div',{staticClass:"rules-item"},[_vm._v(" Level 1 referral reward: "),_c('em',[_vm._v("100%")])]),_c('div',{staticClass:"rules-item"},[_vm._v(" Level 2 referral reward: "),_c('em',[_vm._v("10%")])]),_c('div',{staticClass:"rules-item"},[_vm._v(" Level 3 referral reward: "),_c('em',[_vm._v("10%")])]),_c('div',{staticClass:"rules-item"},[_vm._v(" Level 4 referral reward: "),_c('em',[_vm._v("10%")])]),_c('div',{staticClass:"rules-item"},[_vm._v(" Level 5 referral reward: "),_c('em',[_vm._v("10%")])])])]),_c('b-row',{staticClass:"invitation-container",attrs:{"align-h":"between"}},[_c('b-col',{staticClass:"left",attrs:{"lg":"6","order":"1","order-md":"1"}},[_c('div',{staticClass:"invite-card"},[_c('div',{staticClass:"invite-head"},[_c('span',{class:{ active: _vm.active === 1},on:{"click":function($event){return _vm.changeInviteCard(1)}}},[_vm._v("Referral friends")])]),_c('div',{directives:[{name:"show",rawName:"v-show",value:(_vm.active === 1),expression:"active === 1"}]},[(_vm.user.positionOpened)?[_c('div',{staticClass:"invite-body"},[_c('span',[_vm._v("Referral link")]),_c('span',[_vm._v(" "+_vm._s(_vm._f("ellipsis")((_vm.link)))+" "),_c('img',{staticClass:"copy-btn",attrs:{"src":__webpack_require__("de28"),"alt":""}})])]),_c('b-button',{staticClass:"invite-btn copy-btn",attrs:{"variant":"primary"}},[_vm._v(" Referral friends ")])]:[_c('div',{staticClass:"not-invited"},[_vm._v(" You have not been invited "),_c('img',{staticClass:"question",attrs:{"id":"tooltip-target","src":__webpack_require__("905f"),"alt":""}}),_c('b-tooltip',{attrs:{"target":"tooltip-target","triggers":"hover"}},[_vm._v(" Hold USDT financial management ")])],1),(_vm.user.address)?_c('b-button',{staticClass:"invite-btn",attrs:{"variant":"primary"},on:{"click":_vm.onScrollTo}},[_vm._v(" Qualified for Invitation ")]):_c('b-button',{staticClass:"invite-btn",attrs:{"variant":"primary"},on:{"click":_vm.unlock}},[_vm._v(" Connet Wallet ")])]],2),_c('div',{directives:[{name:"show",rawName:"v-show",value:(_vm.active === 2),expression:"active === 2"}]},[_c('table',{staticClass:"reward-table"},[_c('thead',{staticClass:"table-head"},[_c('tr',[_c('th',[_vm._v("Type")]),_c('th',[_vm._v("Claimable")])])]),_c('tbody',_vm._l((_vm.list),function(item){return _c('tr',{staticClass:"table-row"},[_c('td',[_vm._v(_vm._s(item.type))]),_c('td',[_vm._v(_vm._s(item.claimable))])])}),0)]),_c('b-button',{staticClass:"claim-btn",attrs:{"variant":"primary"}},[_vm._v(" Redeem ")])],1)])]),_c('b-col',{staticClass:"right",attrs:{"lg":"6","order":"2","order-md":"2"}},[_c('div',{staticClass:"invite-pic"},[_c('img',{attrs:{"src":__webpack_require__("da5e"),"alt":""}})])])],1)],1)],1)}
var Invitationvue_type_template_id_597e9484_scoped_true_staticRenderFns = []


// CONCATENATED MODULE: ./src/views/Home/components/Invitation.vue?vue&type=template&id=597e9484&scoped=true&

// EXTERNAL MODULE: ./node_modules/clipboard/dist/clipboard.js
var dist_clipboard = __webpack_require__("b311");
var clipboard_default = /*#__PURE__*/__webpack_require__.n(dist_clipboard);

// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/components/Invitation.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//




/* harmony default export */ var Invitationvue_type_script_lang_js_ = ({
  components: {},
  filters: {
    ellipsis(address) {
      return address.replace(/^(.{14}).*(.{4})$/, '$1...$2');
    }
  },
  data() {
    return {
      active: 1,
      list: [{
        type: '222',
        claimable: '1'
      }, {
        type: '222',
        claimable: '1'
      }]
    };
  },
  computed: {
    ...Object(vuex_esm["c" /* mapState */])(['user']),
    link() {
      return `${config["a" /* default */].webUrl}/#/?refer=${this.user.address}`;
    }
  },
  created() {
    const clipboard = new clipboard_default.a('.copy-btn', {
      text: () => this.link
    });
    clipboard.on('success', e => {
      this.showSuccess('Copied', {
        title: 'Notice',
        autoHideDelay: 5000
      });
      e.clearSelection();
    });
  },
  methods: {
    onClick(val) {
      if (this.active === val) {
        this.active = '';
      } else {
        this.active = val;
      }
    },
    changeInviteCard(id) {
      this.active = id;
    },
    unlock() {
      this.$store.dispatch('unlockByMetaMask');
    },
    onScrollTo() {
      const targetElement = document.getElementById('Earn');
      const targetPosition = targetElement.getBoundingClientRect().top + window.pageYOffset;
      window.scrollTo({
        top: targetPosition,
        behavior: 'smooth'
      });
    }
  }
});
// CONCATENATED MODULE: ./src/views/Home/components/Invitation.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_Invitationvue_type_script_lang_js_ = (Invitationvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/components/Invitation.vue?vue&type=style&index=0&id=597e9484&prod&lang=scss&scoped=true&
var Invitationvue_type_style_index_0_id_597e9484_prod_lang_scss_scoped_true_ = __webpack_require__("a3f0");

// CONCATENATED MODULE: ./src/views/Home/components/Invitation.vue






/* normalize component */

var Invitation_component = Object(componentNormalizer["a" /* default */])(
  components_Invitationvue_type_script_lang_js_,
  Invitationvue_type_template_id_597e9484_scoped_true_render,
  Invitationvue_type_template_id_597e9484_scoped_true_staticRenderFns,
  false,
  null,
  "597e9484",
  null
  
)

/* harmony default export */ var Invitation = (Invitation_component.exports);
// CONCATENATED MODULE: ./node_modules/cache-loader/dist/cjs.js??ref--13-0!./node_modules/thread-loader/dist/cjs.js!./node_modules/babel-loader/lib!./node_modules/cache-loader/dist/cjs.js??ref--1-0!./node_modules/vue-loader/lib??vue-loader-options!./src/views/Home/index.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//

// @ is an alias to /src





/* harmony default export */ var Homevue_type_script_lang_js_ = ({
  name: 'Home',
  components: {
    Banner: Banner,
    Marshmallow: Marshmallow,
    CommonProblem: CommonProblem,
    Recommend: Recommend,
    Invitation: Invitation
  }
});
// CONCATENATED MODULE: ./src/views/Home/index.vue?vue&type=script&lang=js&
 /* harmony default export */ var views_Homevue_type_script_lang_js_ = (Homevue_type_script_lang_js_); 
// EXTERNAL MODULE: ./src/views/Home/index.vue?vue&type=style&index=0&id=a1a8b50e&prod&lang=scss&scoped=true&
var Homevue_type_style_index_0_id_a1a8b50e_prod_lang_scss_scoped_true_ = __webpack_require__("8af8");

// CONCATENATED MODULE: ./src/views/Home/index.vue






/* normalize component */

var Home_component = Object(componentNormalizer["a" /* default */])(
  views_Homevue_type_script_lang_js_,
  render,
  staticRenderFns,
  false,
  null,
  "a1a8b50e",
  null
  
)

/* harmony default export */ var Home = __webpack_exports__["default"] = (Home_component.exports);

/***/ }),

/***/ "182d":
/***/ (function(module, exports, __webpack_require__) {

var toPositiveInteger = __webpack_require__("f8cd");

var $RangeError = RangeError;

module.exports = function (it, BYTES) {
  var offset = toPositiveInteger(it);
  if (offset % BYTES) throw $RangeError('Wrong offset');
  return offset;
};


/***/ }),

/***/ "1b3b":
/***/ (function(module, exports, __webpack_require__) {

// TODO: Remove from `core-js@4`
__webpack_require__("6ce5");


/***/ }),

/***/ "1d02":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var ArrayBufferViewCore = __webpack_require__("ebb5");
var $findLastIndex = __webpack_require__("a258").findLastIndex;

var aTypedArray = ArrayBufferViewCore.aTypedArray;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;

// `%TypedArray%.prototype.findLastIndex` method
// https://github.com/tc39/proposal-array-find-from-last
exportTypedArrayMethod('findLastIndex', function findLastIndex(predicate /* , thisArg */) {
  return $findLastIndex(aTypedArray(this), predicate, arguments.length > 1 ? arguments[1] : undefined);
});


/***/ }),

/***/ "1e5d":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Marshmallow_vue_vue_type_style_index_0_id_01415f38_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("2675");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Marshmallow_vue_vue_type_style_index_0_id_01415f38_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Marshmallow_vue_vue_type_style_index_0_id_01415f38_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "2675":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "2834":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var ArrayBufferViewCore = __webpack_require__("ebb5");
var uncurryThis = __webpack_require__("e330");
var aCallable = __webpack_require__("59ed");
var arrayFromConstructorAndList = __webpack_require__("dfb9");

var aTypedArray = ArrayBufferViewCore.aTypedArray;
var getTypedArrayConstructor = ArrayBufferViewCore.getTypedArrayConstructor;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;
var sort = uncurryThis(ArrayBufferViewCore.TypedArrayPrototype.sort);

// `%TypedArray%.prototype.toSorted` method
// https://tc39.es/proposal-change-array-by-copy/#sec-%typedarray%.prototype.toSorted
exportTypedArrayMethod('toSorted', function toSorted(compareFn) {
  if (compareFn !== undefined) aCallable(compareFn);
  var O = aTypedArray(this);
  var A = arrayFromConstructorAndList(getTypedArrayConstructor(O), O);
  return sort(A, compareFn);
});


/***/ }),

/***/ "2c97":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "3511":
/***/ (function(module, exports) {

var $TypeError = TypeError;
var MAX_SAFE_INTEGER = 0x1FFFFFFFFFFFFF; // 2 ** 53 - 1 == 9007199254740991

module.exports = function (it) {
  if (it > MAX_SAFE_INTEGER) throw $TypeError('Maximum allowed index exceeded');
  return it;
};


/***/ }),

/***/ "3a34":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var DESCRIPTORS = __webpack_require__("83ab");
var isArray = __webpack_require__("e8b5");

var $TypeError = TypeError;
// eslint-disable-next-line es/no-object-getownpropertydescriptor -- safe
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;

// Safari < 13 does not throw an error in this case
var SILENT_ON_NON_WRITABLE_LENGTH_SET = DESCRIPTORS && !function () {
  // makes no sense without proper strict mode support
  if (this !== undefined) return true;
  try {
    // eslint-disable-next-line es/no-object-defineproperty -- safe
    Object.defineProperty([], 'length', { writable: false }).length = 1;
  } catch (error) {
    return error instanceof TypeError;
  }
}();

module.exports = SILENT_ON_NON_WRITABLE_LENGTH_SET ? function (O, length) {
  if (isArray(O) && !getOwnPropertyDescriptor(O, 'length').writable) {
    throw $TypeError('Cannot set read only .length');
  } return O.length = length;
} : function (O, length) {
  return O.length = length;
};


/***/ }),

/***/ "3c5d":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var global = __webpack_require__("da84");
var call = __webpack_require__("c65b");
var ArrayBufferViewCore = __webpack_require__("ebb5");
var lengthOfArrayLike = __webpack_require__("07fa");
var toOffset = __webpack_require__("182d");
var toIndexedObject = __webpack_require__("7b0b");
var fails = __webpack_require__("d039");

var RangeError = global.RangeError;
var Int8Array = global.Int8Array;
var Int8ArrayPrototype = Int8Array && Int8Array.prototype;
var $set = Int8ArrayPrototype && Int8ArrayPrototype.set;
var aTypedArray = ArrayBufferViewCore.aTypedArray;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;

var WORKS_WITH_OBJECTS_AND_GEERIC_ON_TYPED_ARRAYS = !fails(function () {
  // eslint-disable-next-line es/no-typed-arrays -- required for testing
  var array = new Uint8ClampedArray(2);
  call($set, array, { length: 1, 0: 3 }, 1);
  return array[1] !== 3;
});

// https://bugs.chromium.org/p/v8/issues/detail?id=11294 and other
var TO_OBJECT_BUG = WORKS_WITH_OBJECTS_AND_GEERIC_ON_TYPED_ARRAYS && ArrayBufferViewCore.NATIVE_ARRAY_BUFFER_VIEWS && fails(function () {
  var array = new Int8Array(2);
  array.set(1);
  array.set('2', 1);
  return array[0] !== 0 || array[1] !== 2;
});

// `%TypedArray%.prototype.set` method
// https://tc39.es/ecma262/#sec-%typedarray%.prototype.set
exportTypedArrayMethod('set', function set(arrayLike /* , offset */) {
  aTypedArray(this);
  var offset = toOffset(arguments.length > 1 ? arguments[1] : undefined, 1);
  var src = toIndexedObject(arrayLike);
  if (WORKS_WITH_OBJECTS_AND_GEERIC_ON_TYPED_ARRAYS) return call($set, this, src, offset);
  var length = this.length;
  var len = lengthOfArrayLike(src);
  var index = 0;
  if (len + offset > length) throw RangeError('Wrong length');
  while (index < len) this[offset + index] = src[index++];
}, !WORKS_WITH_OBJECTS_AND_GEERIC_ON_TYPED_ARRAYS || TO_OBJECT_BUG);


/***/ }),

/***/ "3d71":
/***/ (function(module, exports, __webpack_require__) {

// TODO: Remove from `core-js@4`
__webpack_require__("2834");


/***/ }),

/***/ "3f1d":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "4625":
/***/ (function(module, exports, __webpack_require__) {

var classofRaw = __webpack_require__("c6b6");
var uncurryThis = __webpack_require__("e330");

module.exports = function (fn) {
  // Nashorn bug:
  //   https://github.com/zloirock/core-js/issues/1128
  //   https://github.com/zloirock/core-js/issues/1130
  if (classofRaw(fn) === 'Function') return uncurryThis(fn);
};


/***/ }),

/***/ "473b":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "4a84":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _fragments__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("c167");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "ConstructorFragment", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["a"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "ErrorFragment", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["b"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "EventFragment", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["c"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "Fragment", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["e"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "FunctionFragment", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["f"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "ParamType", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["g"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "FormatTypes", function() { return _fragments__WEBPACK_IMPORTED_MODULE_0__["d"]; });

/* harmony import */ var _abi_coder__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__("5791");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "AbiCoder", function() { return _abi_coder__WEBPACK_IMPORTED_MODULE_1__["a"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "defaultAbiCoder", function() { return _abi_coder__WEBPACK_IMPORTED_MODULE_1__["b"]; });

/* harmony import */ var _interface__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__("a807");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "Interface", function() { return _interface__WEBPACK_IMPORTED_MODULE_2__["b"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "Indexed", function() { return _interface__WEBPACK_IMPORTED_MODULE_2__["a"]; });

/* harmony import */ var _interface__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__("5134");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "checkResultErrors", function() { return _interface__WEBPACK_IMPORTED_MODULE_3__["d"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "LogDescription", function() { return _interface__WEBPACK_IMPORTED_MODULE_2__["c"]; });

/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "TransactionDescription", function() { return _interface__WEBPACK_IMPORTED_MODULE_2__["d"]; });






//# sourceMappingURL=index.js.map

/***/ }),

/***/ "4b11":
/***/ (function(module, exports) {

// eslint-disable-next-line es/no-typed-arrays -- safe
module.exports = typeof ArrayBuffer != 'undefined' && typeof DataView != 'undefined';


/***/ }),

/***/ "4ea1":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var arrayWith = __webpack_require__("d429");
var ArrayBufferViewCore = __webpack_require__("ebb5");
var isBigIntArray = __webpack_require__("bcbf");
var toIntegerOrInfinity = __webpack_require__("5926");
var toBigInt = __webpack_require__("f495");

var aTypedArray = ArrayBufferViewCore.aTypedArray;
var getTypedArrayConstructor = ArrayBufferViewCore.getTypedArrayConstructor;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;

var PROPER_ORDER = !!function () {
  try {
    // eslint-disable-next-line no-throw-literal, es/no-typed-arrays, es/no-array-prototype-with -- required for testing
    new Int8Array(1)['with'](2, { valueOf: function () { throw 8; } });
  } catch (error) {
    // some early implementations, like WebKit, does not follow the final semantic
    // https://github.com/tc39/proposal-change-array-by-copy/pull/86
    return error === 8;
  }
}();

// `%TypedArray%.prototype.with` method
// https://tc39.es/proposal-change-array-by-copy/#sec-%typedarray%.prototype.with
exportTypedArrayMethod('with', { 'with': function (index, value) {
  var O = aTypedArray(this);
  var relativeIndex = toIntegerOrInfinity(index);
  var actualValue = isBigIntArray(O) ? toBigInt(value) : +value;
  return arrayWith(O, getTypedArrayConstructor(O), relativeIndex, actualValue);
} }['with'], !PROPER_ORDER);


/***/ }),

/***/ "5220":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.add = exports.toBig = exports.split = exports.fromBig = void 0;
const U32_MASK64 = BigInt(2 ** 32 - 1);
const _32n = BigInt(32);
// We are not using BigUint64Array, because they are extremely slow as per 2022
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
exports.fromBig = fromBig;
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
exports.split = split;
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
exports.toBig = toBig;
// for Shift in [0, 32)
const shrSH = (h, l, s) => h >>> s;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (h, l) => l;
const rotr32L = (h, l) => h;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
// Removing "export" has 5% perf penalty -_-
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
exports.add = add;
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
// prettier-ignore
const u64 = {
    fromBig, split, toBig: exports.toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};
exports.default = u64;
//# sourceMappingURL=_u64.js.map

/***/ }),

/***/ "531d":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomBytes = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
// The import here is via the package name. This is to ensure
// that exports mapping/resolution does fall into place.
const crypto_1 = __webpack_require__("cae7");
// Cast array to different type
const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
exports.u8 = u8;
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
exports.u32 = u32;
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
exports.createView = createView;
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
exports.rotr = rotr;
exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
// So, just to be sure not to corrupt anything.
if (!exports.isLE)
    throw new Error('Non little-endian hardware is not supported');
const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
/**
 * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
 */
function bytesToHex(uint8a) {
    // pre-caching improves the speed 6x
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Uint8Array expected');
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes[uint8a[i]];
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
/**
 * @example hexToBytes('deadbeef')
 */
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
exports.hexToBytes = hexToBytes;
// There is no setImmediate in browser and setTimeout is slow. However, call to async function will return Promise
// which will be fullfiled only on next scheduler queue processing step and this is exactly what we need.
const nextTick = async () => { };
exports.nextTick = nextTick;
// Returns control to thread each 'tick' ms to avoid blocking
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await (0, exports.nextTick)();
        ts += diff;
    }
}
exports.asyncLoop = asyncLoop;
function utf8ToBytes(str) {
    if (typeof str !== 'string') {
        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
exports.utf8ToBytes = utf8ToBytes;
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
exports.toBytes = toBytes;
/**
 * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
 * @example concatBytes(buf1, buf2)
 */
function concatBytes(...arrays) {
    if (!arrays.every((a) => a instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
exports.concatBytes = concatBytes;
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
exports.Hash = Hash;
// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
function checkOpts(defaults, opts) {
    if (opts !== undefined && (typeof opts !== 'object' || !isPlainObject(opts)))
        throw new TypeError('Options should be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
exports.checkOpts = checkOpts;
function wrapConstructor(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    return hashC;
}
exports.wrapConstructor = wrapConstructor;
function wrapConstructorWithOpts(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    return hashC;
}
exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
/**
 * Secure PRNG
 */
function randomBytes(bytesLength = 32) {
    if (crypto_1.crypto.web) {
        return crypto_1.crypto.web.getRandomValues(new Uint8Array(bytesLength));
    }
    else if (crypto_1.crypto.node) {
        return new Uint8Array(crypto_1.crypto.node.randomBytes(bytesLength).buffer);
    }
    else {
        throw new Error("The environment doesn't have randomBytes function");
    }
}
exports.randomBytes = randomBytes;
//# sourceMappingURL=utils.js.map

/***/ }),

/***/ "58bc":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Subscribe_vue_vue_type_style_index_0_id_f04610f4_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("3f1d");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Subscribe_vue_vue_type_style_index_0_id_f04610f4_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Subscribe_vue_vue_type_style_index_0_id_f04610f4_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "60a3":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Claim_vue_vue_type_style_index_0_id_6f72bcac_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("ab9f");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Claim_vue_vue_type_style_index_0_id_6f72bcac_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Claim_vue_vue_type_style_index_0_id_6f72bcac_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "6134":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "61d1":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "6ce5":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var arrayToReversed = __webpack_require__("df7e");
var ArrayBufferViewCore = __webpack_require__("ebb5");

var aTypedArray = ArrayBufferViewCore.aTypedArray;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;
var getTypedArrayConstructor = ArrayBufferViewCore.getTypedArrayConstructor;

// `%TypedArray%.prototype.toReversed` method
// https://tc39.es/proposal-change-array-by-copy/#sec-%typedarray%.prototype.toReversed
exportTypedArrayMethod('toReversed', function toReversed() {
  return arrayToReversed(aTypedArray(this), getTypedArrayConstructor(this));
});


/***/ }),

/***/ "6daf":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


__webpack_require__("d9e2");
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.StandardMerkleTree = void 0;
const keccak_1 = __webpack_require__("a623");
const utils_1 = __webpack_require__("cc7b");
const abi_1 = __webpack_require__("4a84");
const bytes_1 = __webpack_require__("fb21");
const core_1 = __webpack_require__("d6c1");
const check_bounds_1 = __webpack_require__("d640");
const throw_error_1 = __webpack_require__("001f");
function standardLeafHash(value, types) {
  return (0, keccak_1.keccak256)((0, keccak_1.keccak256)((0, utils_1.hexToBytes)(abi_1.defaultAbiCoder.encode(types, value))));
}
class StandardMerkleTree {
  constructor(tree, values, leafEncoding) {
    this.tree = tree;
    this.values = values;
    this.leafEncoding = leafEncoding;
    this.hashLookup = Object.fromEntries(values.map(({
      value
    }, valueIndex) => [(0, bytes_1.hex)(standardLeafHash(value, leafEncoding)), valueIndex]));
  }
  static of(values, leafEncoding) {
    const hashedValues = values.map((value, valueIndex) => ({
      value,
      valueIndex,
      hash: standardLeafHash(value, leafEncoding)
    })).sort((a, b) => (0, bytes_1.compareBytes)(a.hash, b.hash));
    const tree = (0, core_1.makeMerkleTree)(hashedValues.map(v => v.hash));
    const indexedValues = values.map(value => ({
      value,
      treeIndex: 0
    }));
    for (const [leafIndex, {
      valueIndex
    }] of hashedValues.entries()) {
      indexedValues[valueIndex].treeIndex = tree.length - leafIndex - 1;
    }
    return new StandardMerkleTree(tree, indexedValues, leafEncoding);
  }
  static load(data) {
    if (data.format !== 'standard-v1') {
      throw new Error(`Unknown format '${data.format}'`);
    }
    return new StandardMerkleTree(data.tree.map(utils_1.hexToBytes), data.values, data.leafEncoding);
  }
  dump() {
    return {
      format: 'standard-v1',
      tree: this.tree.map(bytes_1.hex),
      values: this.values,
      leafEncoding: this.leafEncoding
    };
  }
  render() {
    return (0, core_1.renderMerkleTree)(this.tree);
  }
  get root() {
    return (0, bytes_1.hex)(this.tree[0]);
  }
  *entries() {
    for (const [i, {
      value
    }] of this.values.entries()) {
      yield [i, value];
    }
  }
  validate() {
    for (let i = 0; i < this.values.length; i++) {
      this.validateValue(i);
    }
    if (!(0, core_1.isValidMerkleTree)(this.tree)) {
      throw new Error('Merkle tree is invalid');
    }
  }
  leafHash(leaf) {
    return (0, bytes_1.hex)(standardLeafHash(leaf, this.leafEncoding));
  }
  leafLookup(leaf) {
    var _this$hashLookup$this;
    return (_this$hashLookup$this = this.hashLookup[this.leafHash(leaf)]) !== null && _this$hashLookup$this !== void 0 ? _this$hashLookup$this : (0, throw_error_1.throwError)('Leaf is not in tree');
  }
  getProof(leaf) {
    // input validity
    const valueIndex = typeof leaf === 'number' ? leaf : this.leafLookup(leaf);
    this.validateValue(valueIndex);
    // rebuild tree index and generate proof
    const {
      treeIndex
    } = this.values[valueIndex];
    const proof = (0, core_1.getProof)(this.tree, treeIndex);
    // sanity check proof
    if (!this._verify(this.tree[treeIndex], proof)) {
      throw new Error('Unable to prove value');
    }
    // return proof in hex format
    return proof.map(bytes_1.hex);
  }
  getMultiProof(leaves) {
    // input validity
    const valueIndices = leaves.map(leaf => typeof leaf === 'number' ? leaf : this.leafLookup(leaf));
    for (const valueIndex of valueIndices) this.validateValue(valueIndex);
    // rebuild tree indices and generate proof
    const indices = valueIndices.map(i => this.values[i].treeIndex);
    const proof = (0, core_1.getMultiProof)(this.tree, indices);
    // sanity check proof
    if (!this._verifyMultiProof(proof)) {
      throw new Error('Unable to prove values');
    }
    // return multiproof in hex format
    return {
      leaves: proof.leaves.map(hash => this.values[this.hashLookup[(0, bytes_1.hex)(hash)]].value),
      proof: proof.proof.map(bytes_1.hex),
      proofFlags: proof.proofFlags
    };
  }
  verify(leaf, proof) {
    return this._verify(this.getLeafHash(leaf), proof.map(utils_1.hexToBytes));
  }
  _verify(leafHash, proof) {
    const impliedRoot = (0, core_1.processProof)(leafHash, proof);
    return (0, utils_1.equalsBytes)(impliedRoot, this.tree[0]);
  }
  verifyMultiProof(multiproof) {
    return this._verifyMultiProof({
      leaves: multiproof.leaves.map(l => this.getLeafHash(l)),
      proof: multiproof.proof.map(utils_1.hexToBytes),
      proofFlags: multiproof.proofFlags
    });
  }
  _verifyMultiProof(multiproof) {
    const impliedRoot = (0, core_1.processMultiProof)(multiproof);
    return (0, utils_1.equalsBytes)(impliedRoot, this.tree[0]);
  }
  validateValue(valueIndex) {
    (0, check_bounds_1.checkBounds)(this.values, valueIndex);
    const {
      value,
      treeIndex
    } = this.values[valueIndex];
    (0, check_bounds_1.checkBounds)(this.tree, treeIndex);
    const leaf = standardLeafHash(value, this.leafEncoding);
    if (!(0, utils_1.equalsBytes)(leaf, this.tree[treeIndex])) {
      throw new Error('Merkle tree does not contain the expected value');
    }
    return leaf;
  }
  getLeafHash(leaf) {
    if (typeof leaf === 'number') {
      return this.validateValue(leaf);
    } else {
      return standardLeafHash(leaf, this.leafEncoding);
    }
  }
}
exports.StandardMerkleTree = StandardMerkleTree;

/***/ }),

/***/ "715f":
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__("d9e2");
__webpack_require__("14d9");
/**
 * 生成页码数组
 * @author Qizhong Fang <qizhong.fang@outlook.com>
 * @version 0.0.1
 */

/**
 * 生成带省略号的页码数组
 * @param {Number} showPageCount - 显示页码数量
 * @param {Number} currentPage - 当前页码
 * @param {Number} pageCount - 总页面数
 * @returns {Array} 页码数组
 */
function generatePagination({
  showPageCount = 10,
  currentPage = 1,
  pageCount = 10
} = {}) {
  if (showPageCount < 1 || currentPage < 1 || pageCount < 1) {
    throw new Error('Pagination options can not be negative.');
    return;
  }
  if (currentPage > pageCount) {
    throw new Error('Current page can not greater than page count.');
    return;
  }
  const ELLIPSIS = '...';
  const pages = [];
  const omit = pageCount - showPageCount;
  let omitLeft;
  let omitRight;
  const showPageMedian = Math.floor(showPageCount / 2);
  if (pageCount > showPageCount) {
    if (currentPage > showPageMedian) {
      omitLeft = Math.min(currentPage - showPageMedian, omit);
      omitRight = omit - omitLeft;
    } else {
      omitLeft = 0;
      omitRight = omit;
    }
    for (let i = 1; i <= pageCount; i++) {
      if (omitLeft > 0) {
        if (i > 1 && i < omitLeft + 3) {
          continue;
        }
      }
      if (omitRight > 0) {
        if (i < pageCount && i > pageCount - omitRight - 2) {
          continue;
        }
      }
      pages.push(i);
    }
    if (omitLeft > 0) {
      pages.splice(1, 0, ELLIPSIS);
    }
    if (omitRight > 0) {
      pages.splice(pages.length - 1, 0, ELLIPSIS);
    }
    return pages;
  }
  for (let i = 1; i <= pageCount; i++) {
    pages.push(i);
  }
  return pages;
}
module.exports = generatePagination;

/***/ }),

/***/ "7357":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "7c21":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "807e":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Recommend_vue_vue_type_style_index_0_id_164d6c28_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("61d1");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Recommend_vue_vue_type_style_index_0_id_164d6c28_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Recommend_vue_vue_type_style_index_0_id_164d6c28_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "8af8":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_id_a1a8b50e_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("b3e0");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_id_a1a8b50e_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_id_a1a8b50e_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "8d34":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "905f":
/***/ (function(module, exports) {

module.exports = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAAAXNSR0IArs4c6QAABJRJREFUWEfNmNtrHFUcx3/fme32Yh/qpQaC2D7VeqEg9CKR7s40O7P7ILUihaYBxVJfim8V0b9AEeuT9KVeKEqiULFewOzuxJ1dEW2JUtFY61MbQtCWagteapqZr5zdbNwkk50zu1EyT7tzfud7PvM75/zO73cgK/zBCueTrgFHR7/YFATBZpGwNxT0qg82hFMixpRpmhf7+x++1I0TOgIcGa3tRMjHRPgoyXvbAQA4L4IPaeCDQn/mbFLYRIClUmU7gZdJ2kkHUvYAKiCfc117TLe/FmClUtnw9wyOQ+QASa0+SwEAIEXeXZ3iEdu2r8WBxg7meZ9vmWHwsZBb4sQStUMupJDam8vt/qntEmnXWCrVskR4muSGRINrGgO4Bhr7XDdTXdLjSzUozwUMzujCAbhBYX3HQrCJ5BodTgVpwty1lCcjp3h2zZ3Rm1ZcMUSOrl+fPtXX1/eXghobG1t39dof+4XhMVJujwWFXFidkoei1mQk4EjZHxJyIE4YgvLaNcZgJpO5EmXreV/1BLwxrLXrgeGCYx1cqLMI0PP8HQFFTW37DQT8nMLaB3K5XVeVaKnkD4SG7AGFFKNYcDLvq/e1Wm3jnzfCcRFujImXBLlzYQhaBFEs+5/pfDEM2Z/P2afUhxS96mkh97YCABjKO9agelf0qoMMw3diZwSo5B1rzzyd1j/qhJAgOBMvJNfTKbnDtu2ZYrl6iAzfiOpjCA66rjU8Pj6enpy6cpXk+jhtMc1drSfOPA8Wy9UXyfD5OBGIfJ137e1175T8YQoPRPYB3i441hOqbaTsfyPkg7HaMF7KO9kXmnbzAUv+eQq3xooIfk2v4iZlN30Tlyi8LdKDwFuuYx2qA5Yq34vI/bHawPm8Y923CFBlJTeD6YtxAv+247fGb94a1QeCywbMHY6ze2J2N0+STOnorzLTm5tZ0JwH1akRSuDrCMTZAHIdKbFc2z5X957nn5CQh+P6NdsNMa3m6dIC6A+EwiFdkaXsAPxuQtxczvpydu09JeSbSXSbm0v1mQMcKVWPioSvJBFabIsQpjyS77c+bcDVHhcG74mImUzXeLbgZo/9F4CvFlzrqBIuer7DUD4RYToZnLKOAKyfBN1NcZAy1vWok6VYqWyVmzJGkVuSw6mSoRE/53mw600C/FBwrHoYKZb9kyTr8a+TJ3KTJA8z84cGpJp3bKsBWPFJyXYCp/pEhpm6sGagjhp4uQBVkRUZqBtfrnfULQH4y129d96t2ianLk+Q0tOJB9HuqNNNFtrEwAnVRrIO2tHTLlmYXeBa6VZHg8d0UmVp23RL9Z+tfc/GJqyR8yyNWwRKPZFI8qhyVCthVaK6KX8rAIDjbi77TP0jveprJI8kARTdlF+JJiuaGhgmjG2Ok/1O/fa82raZMPhWGzBp0dQYJFnZaYg87br267PL5HAockIHsKOysymcrHDHNCAnG7tYntQ5g7sq3JuQjauPmY+Eco+OR7RtluPqoznYir48avXIir1+WzhtcxeY5L64IguCHwU4/b9cYEatrxV5Bay9EZbBMPYCcxnG6EriH/yeRkejx2WkAAAAAElFTkSuQmCC"

/***/ }),

/***/ "907a":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var ArrayBufferViewCore = __webpack_require__("ebb5");
var lengthOfArrayLike = __webpack_require__("07fa");
var toIntegerOrInfinity = __webpack_require__("5926");

var aTypedArray = ArrayBufferViewCore.aTypedArray;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;

// `%TypedArray%.prototype.at` method
// https://github.com/tc39/proposal-relative-indexing-method
exportTypedArrayMethod('at', function at(index) {
  var O = aTypedArray(this);
  var len = lengthOfArrayLike(O);
  var relativeIndex = toIntegerOrInfinity(index);
  var k = relativeIndex >= 0 ? relativeIndex : len + relativeIndex;
  return (k < 0 || k >= len) ? undefined : O[k];
});


/***/ }),

/***/ "912b":
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__.p + "client/img/gradient@2x.6f7a45a6.png";

/***/ }),

/***/ "986a":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var ArrayBufferViewCore = __webpack_require__("ebb5");
var $findLast = __webpack_require__("a258").findLast;

var aTypedArray = ArrayBufferViewCore.aTypedArray;
var exportTypedArrayMethod = ArrayBufferViewCore.exportTypedArrayMethod;

// `%TypedArray%.prototype.findLast` method
// https://github.com/tc39/proposal-array-find-from-last
exportTypedArrayMethod('findLast', function findLast(predicate /* , thisArg */) {
  return $findLast(aTypedArray(this), predicate, arguments.length > 1 ? arguments[1] : undefined);
});


/***/ }),

/***/ "9f4d":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Pagination_vue_vue_type_style_index_0_id_7b09cf62_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("8d34");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Pagination_vue_vue_type_style_index_0_id_7b09cf62_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Pagination_vue_vue_type_style_index_0_id_7b09cf62_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "a258":
/***/ (function(module, exports, __webpack_require__) {

var bind = __webpack_require__("0366");
var IndexedObject = __webpack_require__("44ad");
var toObject = __webpack_require__("7b0b");
var lengthOfArrayLike = __webpack_require__("07fa");

// `Array.prototype.{ findLast, findLastIndex }` methods implementation
var createMethod = function (TYPE) {
  var IS_FIND_LAST_INDEX = TYPE == 1;
  return function ($this, callbackfn, that) {
    var O = toObject($this);
    var self = IndexedObject(O);
    var boundFunction = bind(callbackfn, that);
    var index = lengthOfArrayLike(self);
    var value, result;
    while (index-- > 0) {
      value = self[index];
      result = boundFunction(value, index, O);
      if (result) switch (TYPE) {
        case 0: return value; // findLast
        case 1: return index; // findLastIndex
      }
    }
    return IS_FIND_LAST_INDEX ? -1 : undefined;
  };
};

module.exports = {
  // `Array.prototype.findLast` method
  // https://github.com/tc39/proposal-array-find-from-last
  findLast: createMethod(0),
  // `Array.prototype.findLastIndex` method
  // https://github.com/tc39/proposal-array-find-from-last
  findLastIndex: createMethod(1)
};


/***/ }),

/***/ "a3f0":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Invitation_vue_vue_type_style_index_0_id_597e9484_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("7c21");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Invitation_vue_vue_type_style_index_0_id_597e9484_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Invitation_vue_vue_type_style_index_0_id_597e9484_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "a623":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.keccak512 = exports.keccak384 = exports.keccak256 = exports.keccak224 = void 0;
const sha3_1 = __webpack_require__("00e3");
const utils_1 = __webpack_require__("cc7b");
exports.keccak224 = (0, utils_1.wrapHash)(sha3_1.keccak_224);
exports.keccak256 = (() => {
  const k = (0, utils_1.wrapHash)(sha3_1.keccak_256);
  k.create = sha3_1.keccak_256.create;
  return k;
})();
exports.keccak384 = (0, utils_1.wrapHash)(sha3_1.keccak_384);
exports.keccak512 = (0, utils_1.wrapHash)(sha3_1.keccak_512);

/***/ }),

/***/ "ab9f":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "b311":
/***/ (function(module, exports, __webpack_require__) {

/*!
 * clipboard.js v2.0.11
 * https://clipboardjs.com/
 *
 * Licensed MIT © Zeno Rocha
 */
(function webpackUniversalModuleDefinition(root, factory) {
	if(true)
		module.exports = factory();
	else {}
})(this, function() {
return /******/ (function() { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 686:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  "default": function() { return /* binding */ clipboard; }
});

// EXTERNAL MODULE: ./node_modules/tiny-emitter/index.js
var tiny_emitter = __webpack_require__(279);
var tiny_emitter_default = /*#__PURE__*/__webpack_require__.n(tiny_emitter);
// EXTERNAL MODULE: ./node_modules/good-listener/src/listen.js
var listen = __webpack_require__(370);
var listen_default = /*#__PURE__*/__webpack_require__.n(listen);
// EXTERNAL MODULE: ./node_modules/select/src/select.js
var src_select = __webpack_require__(817);
var select_default = /*#__PURE__*/__webpack_require__.n(src_select);
;// CONCATENATED MODULE: ./src/common/command.js
/**
 * Executes a given operation type.
 * @param {String} type
 * @return {Boolean}
 */
function command(type) {
  try {
    return document.execCommand(type);
  } catch (err) {
    return false;
  }
}
;// CONCATENATED MODULE: ./src/actions/cut.js


/**
 * Cut action wrapper.
 * @param {String|HTMLElement} target
 * @return {String}
 */

var ClipboardActionCut = function ClipboardActionCut(target) {
  var selectedText = select_default()(target);
  command('cut');
  return selectedText;
};

/* harmony default export */ var actions_cut = (ClipboardActionCut);
;// CONCATENATED MODULE: ./src/common/create-fake-element.js
/**
 * Creates a fake textarea element with a value.
 * @param {String} value
 * @return {HTMLElement}
 */
function createFakeElement(value) {
  var isRTL = document.documentElement.getAttribute('dir') === 'rtl';
  var fakeElement = document.createElement('textarea'); // Prevent zooming on iOS

  fakeElement.style.fontSize = '12pt'; // Reset box model

  fakeElement.style.border = '0';
  fakeElement.style.padding = '0';
  fakeElement.style.margin = '0'; // Move element out of screen horizontally

  fakeElement.style.position = 'absolute';
  fakeElement.style[isRTL ? 'right' : 'left'] = '-9999px'; // Move element to the same position vertically

  var yPosition = window.pageYOffset || document.documentElement.scrollTop;
  fakeElement.style.top = "".concat(yPosition, "px");
  fakeElement.setAttribute('readonly', '');
  fakeElement.value = value;
  return fakeElement;
}
;// CONCATENATED MODULE: ./src/actions/copy.js



/**
 * Create fake copy action wrapper using a fake element.
 * @param {String} target
 * @param {Object} options
 * @return {String}
 */

var fakeCopyAction = function fakeCopyAction(value, options) {
  var fakeElement = createFakeElement(value);
  options.container.appendChild(fakeElement);
  var selectedText = select_default()(fakeElement);
  command('copy');
  fakeElement.remove();
  return selectedText;
};
/**
 * Copy action wrapper.
 * @param {String|HTMLElement} target
 * @param {Object} options
 * @return {String}
 */


var ClipboardActionCopy = function ClipboardActionCopy(target) {
  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {
    container: document.body
  };
  var selectedText = '';

  if (typeof target === 'string') {
    selectedText = fakeCopyAction(target, options);
  } else if (target instanceof HTMLInputElement && !['text', 'search', 'url', 'tel', 'password'].includes(target === null || target === void 0 ? void 0 : target.type)) {
    // If input type doesn't support `setSelectionRange`. Simulate it. https://developer.mozilla.org/en-US/docs/Web/API/HTMLInputElement/setSelectionRange
    selectedText = fakeCopyAction(target.value, options);
  } else {
    selectedText = select_default()(target);
    command('copy');
  }

  return selectedText;
};

/* harmony default export */ var actions_copy = (ClipboardActionCopy);
;// CONCATENATED MODULE: ./src/actions/default.js
function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }



/**
 * Inner function which performs selection from either `text` or `target`
 * properties and then executes copy or cut operations.
 * @param {Object} options
 */

var ClipboardActionDefault = function ClipboardActionDefault() {
  var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
  // Defines base properties passed from constructor.
  var _options$action = options.action,
      action = _options$action === void 0 ? 'copy' : _options$action,
      container = options.container,
      target = options.target,
      text = options.text; // Sets the `action` to be performed which can be either 'copy' or 'cut'.

  if (action !== 'copy' && action !== 'cut') {
    throw new Error('Invalid "action" value, use either "copy" or "cut"');
  } // Sets the `target` property using an element that will be have its content copied.


  if (target !== undefined) {
    if (target && _typeof(target) === 'object' && target.nodeType === 1) {
      if (action === 'copy' && target.hasAttribute('disabled')) {
        throw new Error('Invalid "target" attribute. Please use "readonly" instead of "disabled" attribute');
      }

      if (action === 'cut' && (target.hasAttribute('readonly') || target.hasAttribute('disabled'))) {
        throw new Error('Invalid "target" attribute. You can\'t cut text from elements with "readonly" or "disabled" attributes');
      }
    } else {
      throw new Error('Invalid "target" value, use a valid Element');
    }
  } // Define selection strategy based on `text` property.


  if (text) {
    return actions_copy(text, {
      container: container
    });
  } // Defines which selection strategy based on `target` property.


  if (target) {
    return action === 'cut' ? actions_cut(target) : actions_copy(target, {
      container: container
    });
  }
};

/* harmony default export */ var actions_default = (ClipboardActionDefault);
;// CONCATENATED MODULE: ./src/clipboard.js
function clipboard_typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { clipboard_typeof = function _typeof(obj) { return typeof obj; }; } else { clipboard_typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return clipboard_typeof(obj); }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); if (superClass) _setPrototypeOf(subClass, superClass); }

function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }

function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = _getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = _getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return _possibleConstructorReturn(this, result); }; }

function _possibleConstructorReturn(self, call) { if (call && (clipboard_typeof(call) === "object" || typeof call === "function")) { return call; } return _assertThisInitialized(self); }

function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }

function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }

function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }






/**
 * Helper function to retrieve attribute value.
 * @param {String} suffix
 * @param {Element} element
 */

function getAttributeValue(suffix, element) {
  var attribute = "data-clipboard-".concat(suffix);

  if (!element.hasAttribute(attribute)) {
    return;
  }

  return element.getAttribute(attribute);
}
/**
 * Base class which takes one or more elements, adds event listeners to them,
 * and instantiates a new `ClipboardAction` on each click.
 */


var Clipboard = /*#__PURE__*/function (_Emitter) {
  _inherits(Clipboard, _Emitter);

  var _super = _createSuper(Clipboard);

  /**
   * @param {String|HTMLElement|HTMLCollection|NodeList} trigger
   * @param {Object} options
   */
  function Clipboard(trigger, options) {
    var _this;

    _classCallCheck(this, Clipboard);

    _this = _super.call(this);

    _this.resolveOptions(options);

    _this.listenClick(trigger);

    return _this;
  }
  /**
   * Defines if attributes would be resolved using internal setter functions
   * or custom functions that were passed in the constructor.
   * @param {Object} options
   */


  _createClass(Clipboard, [{
    key: "resolveOptions",
    value: function resolveOptions() {
      var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      this.action = typeof options.action === 'function' ? options.action : this.defaultAction;
      this.target = typeof options.target === 'function' ? options.target : this.defaultTarget;
      this.text = typeof options.text === 'function' ? options.text : this.defaultText;
      this.container = clipboard_typeof(options.container) === 'object' ? options.container : document.body;
    }
    /**
     * Adds a click event listener to the passed trigger.
     * @param {String|HTMLElement|HTMLCollection|NodeList} trigger
     */

  }, {
    key: "listenClick",
    value: function listenClick(trigger) {
      var _this2 = this;

      this.listener = listen_default()(trigger, 'click', function (e) {
        return _this2.onClick(e);
      });
    }
    /**
     * Defines a new `ClipboardAction` on each click event.
     * @param {Event} e
     */

  }, {
    key: "onClick",
    value: function onClick(e) {
      var trigger = e.delegateTarget || e.currentTarget;
      var action = this.action(trigger) || 'copy';
      var text = actions_default({
        action: action,
        container: this.container,
        target: this.target(trigger),
        text: this.text(trigger)
      }); // Fires an event based on the copy operation result.

      this.emit(text ? 'success' : 'error', {
        action: action,
        text: text,
        trigger: trigger,
        clearSelection: function clearSelection() {
          if (trigger) {
            trigger.focus();
          }

          window.getSelection().removeAllRanges();
        }
      });
    }
    /**
     * Default `action` lookup function.
     * @param {Element} trigger
     */

  }, {
    key: "defaultAction",
    value: function defaultAction(trigger) {
      return getAttributeValue('action', trigger);
    }
    /**
     * Default `target` lookup function.
     * @param {Element} trigger
     */

  }, {
    key: "defaultTarget",
    value: function defaultTarget(trigger) {
      var selector = getAttributeValue('target', trigger);

      if (selector) {
        return document.querySelector(selector);
      }
    }
    /**
     * Allow fire programmatically a copy action
     * @param {String|HTMLElement} target
     * @param {Object} options
     * @returns Text copied.
     */

  }, {
    key: "defaultText",

    /**
     * Default `text` lookup function.
     * @param {Element} trigger
     */
    value: function defaultText(trigger) {
      return getAttributeValue('text', trigger);
    }
    /**
     * Destroy lifecycle.
     */

  }, {
    key: "destroy",
    value: function destroy() {
      this.listener.destroy();
    }
  }], [{
    key: "copy",
    value: function copy(target) {
      var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {
        container: document.body
      };
      return actions_copy(target, options);
    }
    /**
     * Allow fire programmatically a cut action
     * @param {String|HTMLElement} target
     * @returns Text cutted.
     */

  }, {
    key: "cut",
    value: function cut(target) {
      return actions_cut(target);
    }
    /**
     * Returns the support of the given action, or all actions if no action is
     * given.
     * @param {String} [action]
     */

  }, {
    key: "isSupported",
    value: function isSupported() {
      var action = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : ['copy', 'cut'];
      var actions = typeof action === 'string' ? [action] : action;
      var support = !!document.queryCommandSupported;
      actions.forEach(function (action) {
        support = support && !!document.queryCommandSupported(action);
      });
      return support;
    }
  }]);

  return Clipboard;
}((tiny_emitter_default()));

/* harmony default export */ var clipboard = (Clipboard);

/***/ }),

/***/ 828:
/***/ (function(module) {

var DOCUMENT_NODE_TYPE = 9;

/**
 * A polyfill for Element.matches()
 */
if (typeof Element !== 'undefined' && !Element.prototype.matches) {
    var proto = Element.prototype;

    proto.matches = proto.matchesSelector ||
                    proto.mozMatchesSelector ||
                    proto.msMatchesSelector ||
                    proto.oMatchesSelector ||
                    proto.webkitMatchesSelector;
}

/**
 * Finds the closest parent that matches a selector.
 *
 * @param {Element} element
 * @param {String} selector
 * @return {Function}
 */
function closest (element, selector) {
    while (element && element.nodeType !== DOCUMENT_NODE_TYPE) {
        if (typeof element.matches === 'function' &&
            element.matches(selector)) {
          return element;
        }
        element = element.parentNode;
    }
}

module.exports = closest;


/***/ }),

/***/ 438:
/***/ (function(module, __unused_webpack_exports, __webpack_require__) {

var closest = __webpack_require__(828);

/**
 * Delegates event to a selector.
 *
 * @param {Element} element
 * @param {String} selector
 * @param {String} type
 * @param {Function} callback
 * @param {Boolean} useCapture
 * @return {Object}
 */
function _delegate(element, selector, type, callback, useCapture) {
    var listenerFn = listener.apply(this, arguments);

    element.addEventListener(type, listenerFn, useCapture);

    return {
        destroy: function() {
            element.removeEventListener(type, listenerFn, useCapture);
        }
    }
}

/**
 * Delegates event to a selector.
 *
 * @param {Element|String|Array} [elements]
 * @param {String} selector
 * @param {String} type
 * @param {Function} callback
 * @param {Boolean} useCapture
 * @return {Object}
 */
function delegate(elements, selector, type, callback, useCapture) {
    // Handle the regular Element usage
    if (typeof elements.addEventListener === 'function') {
        return _delegate.apply(null, arguments);
    }

    // Handle Element-less usage, it defaults to global delegation
    if (typeof type === 'function') {
        // Use `document` as the first parameter, then apply arguments
        // This is a short way to .unshift `arguments` without running into deoptimizations
        return _delegate.bind(null, document).apply(null, arguments);
    }

    // Handle Selector-based usage
    if (typeof elements === 'string') {
        elements = document.querySelectorAll(elements);
    }

    // Handle Array-like based usage
    return Array.prototype.map.call(elements, function (element) {
        return _delegate(element, selector, type, callback, useCapture);
    });
}

/**
 * Finds closest match and invokes callback.
 *
 * @param {Element} element
 * @param {String} selector
 * @param {String} type
 * @param {Function} callback
 * @return {Function}
 */
function listener(element, selector, type, callback) {
    return function(e) {
        e.delegateTarget = closest(e.target, selector);

        if (e.delegateTarget) {
            callback.call(element, e);
        }
    }
}

module.exports = delegate;


/***/ }),

/***/ 879:
/***/ (function(__unused_webpack_module, exports) {

/**
 * Check if argument is a HTML element.
 *
 * @param {Object} value
 * @return {Boolean}
 */
exports.node = function(value) {
    return value !== undefined
        && value instanceof HTMLElement
        && value.nodeType === 1;
};

/**
 * Check if argument is a list of HTML elements.
 *
 * @param {Object} value
 * @return {Boolean}
 */
exports.nodeList = function(value) {
    var type = Object.prototype.toString.call(value);

    return value !== undefined
        && (type === '[object NodeList]' || type === '[object HTMLCollection]')
        && ('length' in value)
        && (value.length === 0 || exports.node(value[0]));
};

/**
 * Check if argument is a string.
 *
 * @param {Object} value
 * @return {Boolean}
 */
exports.string = function(value) {
    return typeof value === 'string'
        || value instanceof String;
};

/**
 * Check if argument is a function.
 *
 * @param {Object} value
 * @return {Boolean}
 */
exports.fn = function(value) {
    var type = Object.prototype.toString.call(value);

    return type === '[object Function]';
};


/***/ }),

/***/ 370:
/***/ (function(module, __unused_webpack_exports, __webpack_require__) {

var is = __webpack_require__(879);
var delegate = __webpack_require__(438);

/**
 * Validates all params and calls the right
 * listener function based on its target type.
 *
 * @param {String|HTMLElement|HTMLCollection|NodeList} target
 * @param {String} type
 * @param {Function} callback
 * @return {Object}
 */
function listen(target, type, callback) {
    if (!target && !type && !callback) {
        throw new Error('Missing required arguments');
    }

    if (!is.string(type)) {
        throw new TypeError('Second argument must be a String');
    }

    if (!is.fn(callback)) {
        throw new TypeError('Third argument must be a Function');
    }

    if (is.node(target)) {
        return listenNode(target, type, callback);
    }
    else if (is.nodeList(target)) {
        return listenNodeList(target, type, callback);
    }
    else if (is.string(target)) {
        return listenSelector(target, type, callback);
    }
    else {
        throw new TypeError('First argument must be a String, HTMLElement, HTMLCollection, or NodeList');
    }
}

/**
 * Adds an event listener to a HTML element
 * and returns a remove listener function.
 *
 * @param {HTMLElement} node
 * @param {String} type
 * @param {Function} callback
 * @return {Object}
 */
function listenNode(node, type, callback) {
    node.addEventListener(type, callback);

    return {
        destroy: function() {
            node.removeEventListener(type, callback);
        }
    }
}

/**
 * Add an event listener to a list of HTML elements
 * and returns a remove listener function.
 *
 * @param {NodeList|HTMLCollection} nodeList
 * @param {String} type
 * @param {Function} callback
 * @return {Object}
 */
function listenNodeList(nodeList, type, callback) {
    Array.prototype.forEach.call(nodeList, function(node) {
        node.addEventListener(type, callback);
    });

    return {
        destroy: function() {
            Array.prototype.forEach.call(nodeList, function(node) {
                node.removeEventListener(type, callback);
            });
        }
    }
}

/**
 * Add an event listener to a selector
 * and returns a remove listener function.
 *
 * @param {String} selector
 * @param {String} type
 * @param {Function} callback
 * @return {Object}
 */
function listenSelector(selector, type, callback) {
    return delegate(document.body, selector, type, callback);
}

module.exports = listen;


/***/ }),

/***/ 817:
/***/ (function(module) {

function select(element) {
    var selectedText;

    if (element.nodeName === 'SELECT') {
        element.focus();

        selectedText = element.value;
    }
    else if (element.nodeName === 'INPUT' || element.nodeName === 'TEXTAREA') {
        var isReadOnly = element.hasAttribute('readonly');

        if (!isReadOnly) {
            element.setAttribute('readonly', '');
        }

        element.select();
        element.setSelectionRange(0, element.value.length);

        if (!isReadOnly) {
            element.removeAttribute('readonly');
        }

        selectedText = element.value;
    }
    else {
        if (element.hasAttribute('contenteditable')) {
            element.focus();
        }

        var selection = window.getSelection();
        var range = document.createRange();

        range.selectNodeContents(element);
        selection.removeAllRanges();
        selection.addRange(range);

        selectedText = selection.toString();
    }

    return selectedText;
}

module.exports = select;


/***/ }),

/***/ 279:
/***/ (function(module) {

function E () {
  // Keep this empty so it's easier to inherit from
  // (via https://github.com/lipsmack from https://github.com/scottcorgan/tiny-emitter/issues/3)
}

E.prototype = {
  on: function (name, callback, ctx) {
    var e = this.e || (this.e = {});

    (e[name] || (e[name] = [])).push({
      fn: callback,
      ctx: ctx
    });

    return this;
  },

  once: function (name, callback, ctx) {
    var self = this;
    function listener () {
      self.off(name, listener);
      callback.apply(ctx, arguments);
    };

    listener._ = callback
    return this.on(name, listener, ctx);
  },

  emit: function (name) {
    var data = [].slice.call(arguments, 1);
    var evtArr = ((this.e || (this.e = {}))[name] || []).slice();
    var i = 0;
    var len = evtArr.length;

    for (i; i < len; i++) {
      evtArr[i].fn.apply(evtArr[i].ctx, data);
    }

    return this;
  },

  off: function (name, callback) {
    var e = this.e || (this.e = {});
    var evts = e[name];
    var liveEvents = [];

    if (evts && callback) {
      for (var i = 0, len = evts.length; i < len; i++) {
        if (evts[i].fn !== callback && evts[i].fn._ !== callback)
          liveEvents.push(evts[i]);
      }
    }

    // Remove event from queue to prevent memory leak
    // Suggested by https://github.com/lazd
    // Ref: https://github.com/scottcorgan/tiny-emitter/commit/c6ebfaa9bc973b33d110a84a307742b7cf94c953#commitcomment-5024910

    (liveEvents.length)
      ? e[name] = liveEvents
      : delete e[name];

    return this;
  }
};

module.exports = E;
module.exports.TinyEmitter = E;


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		if(__webpack_module_cache__[moduleId]) {
/******/ 			return __webpack_module_cache__[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	!function() {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = function(module) {
/******/ 			var getter = module && module.__esModule ?
/******/ 				function() { return module['default']; } :
/******/ 				function() { return module; };
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	!function() {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = function(exports, definition) {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	!function() {
/******/ 		__webpack_require__.o = function(obj, prop) { return Object.prototype.hasOwnProperty.call(obj, prop); }
/******/ 	}();
/******/ 	
/************************************************************************/
/******/ 	// module exports must be returned from runtime so entry inlining is disabled
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(686);
/******/ })()
.default;
});

/***/ }),

/***/ "b3e0":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "b40a":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.output = exports.exists = exports.hash = exports.bytes = exports.bool = exports.number = void 0;
function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
exports.number = number;
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
exports.bool = bool;
function bytes(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
exports.bytes = bytes;
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
exports.hash = hash;
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
exports.exists = exists;
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
exports.output = output;
const assert = {
    number,
    bool,
    bytes,
    hash,
    exists,
    output,
};
exports.default = assert;
//# sourceMappingURL=_assert.js.map

/***/ }),

/***/ "bcbf":
/***/ (function(module, exports, __webpack_require__) {

var classof = __webpack_require__("f5df");

module.exports = function (it) {
  var klass = classof(it);
  return klass == 'BigInt64Array' || klass == 'BigUint64Array';
};


/***/ }),

/***/ "bfa7":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_CommonProblem_vue_vue_type_style_index_0_id_00cff8cd_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("e00c");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_CommonProblem_vue_vue_type_style_index_0_id_00cff8cd_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_CommonProblem_vue_vue_type_style_index_0_id_00cff8cd_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "c4b3":
/***/ (function(module, exports) {

module.exports = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAdNJREFUWEftlU1O20AUx/9vyIrVBLgGH2colXoAUIBCoVUy41WvwIYjsJqxsoDwUUXiAJWAO7RcIzRedZXOqxzF0cQx2A5B2dirsWy9/+/95nlMWPBFC85HBVAZmDJgjFkOguDvewxnVu0JAGvtDjOfA/gUBMHTPCGMMesAfhLRd631XVJ7DBCG4a5z7hZADUAPwId5QYzCHwGsARgQ0X4CMQYwxnQAHHld94QQ20qp328xEYbhhnPuYRQ+LEVEHa318XCdFO92u0v9fv8awN68IF4I/yGlPGo0Gv8mAOKbGCKKoitm3n8rRLvd3hwMBnHnq+P9JrqVUn5JwqcA5gVRNDwTwIPoMPOBZ+K5VqttN5vNX6/NRFY4gJt6vX7sdz71FaSLjrajFIS1douZ733tr4W/aCA1mJcAPueZyAonomsp5UlW57kGykDE4QAemHnFG7jc8FwDeRBE9FEIQc65ez8cwJXW+oSIXN4ZUvhvOJqJC2Y+9Lr8E69nDS9swDcRRdEEhN9hfMIppb4W6bzwDKQVMrOw1l6kju3h8Vo2vLSBBCYNQUSXSqlvZTqf2UAK4lQIwa1W62yW8JkN5E12meeFv4IyRcu8WwFUBioDCzfwH5A7BDBKkkchAAAAAElFTkSuQmCC"

/***/ }),

/***/ "c6e3":
/***/ (function(module, exports, __webpack_require__) {

// TODO: Remove from `core-js@4`
__webpack_require__("4ea1");


/***/ }),

/***/ "cae7":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.crypto = void 0;
exports.crypto = {
    node: undefined,
    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};
//# sourceMappingURL=cryptoBrowser.js.map

/***/ }),

/***/ "cc7b":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(module) {

__webpack_require__("907a");
__webpack_require__("986a");
__webpack_require__("1d02");
__webpack_require__("3c5d");
__webpack_require__("1b3b");
__webpack_require__("3d71");
__webpack_require__("c6e3");
__webpack_require__("d9e2");
var __importDefault = this && this.__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.crypto = exports.wrapHash = exports.equalsBytes = exports.hexToBytes = exports.bytesToUtf8 = exports.utf8ToBytes = exports.createView = exports.concatBytes = exports.toHex = exports.bytesToHex = exports.assertBytes = exports.assertBool = void 0;
// buf.toString('hex') -> toHex(buf)
const _assert_1 = __importDefault(__webpack_require__("b40a"));
const utils_1 = __webpack_require__("531d");
const assertBool = _assert_1.default.bool;
exports.assertBool = assertBool;
const assertBytes = _assert_1.default.bytes;
exports.assertBytes = assertBytes;
var utils_2 = __webpack_require__("531d");
Object.defineProperty(exports, "bytesToHex", {
  enumerable: true,
  get: function () {
    return utils_2.bytesToHex;
  }
});
Object.defineProperty(exports, "toHex", {
  enumerable: true,
  get: function () {
    return utils_2.bytesToHex;
  }
});
Object.defineProperty(exports, "concatBytes", {
  enumerable: true,
  get: function () {
    return utils_2.concatBytes;
  }
});
Object.defineProperty(exports, "createView", {
  enumerable: true,
  get: function () {
    return utils_2.createView;
  }
});
Object.defineProperty(exports, "utf8ToBytes", {
  enumerable: true,
  get: function () {
    return utils_2.utf8ToBytes;
  }
});
// buf.toString('utf8') -> bytesToUtf8(buf)
function bytesToUtf8(data) {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError(`bytesToUtf8 expected Uint8Array, got ${typeof data}`);
  }
  return new TextDecoder().decode(data);
}
exports.bytesToUtf8 = bytesToUtf8;
function hexToBytes(data) {
  const sliced = data.startsWith("0x") ? data.substring(2) : data;
  return (0, utils_1.hexToBytes)(sliced);
}
exports.hexToBytes = hexToBytes;
// buf.equals(buf2) -> equalsBytes(buf, buf2)
function equalsBytes(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
exports.equalsBytes = equalsBytes;
// Internal utils
function wrapHash(hash) {
  return msg => {
    _assert_1.default.bytes(msg);
    return hash(msg);
  };
}
exports.wrapHash = wrapHash;
exports.crypto = (() => {
  const webCrypto = typeof self === "object" && "crypto" in self ? self.crypto : undefined;
  const nodeRequire =  true && typeof module.require === "function" && module.require.bind(module);
  return {
    node: nodeRequire && !webCrypto ? nodeRequire("crypto") : undefined,
    web: webCrypto
  };
})();
/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__("62e4")(module)))

/***/ }),

/***/ "d429":
/***/ (function(module, exports, __webpack_require__) {

var lengthOfArrayLike = __webpack_require__("07fa");
var toIntegerOrInfinity = __webpack_require__("5926");

var $RangeError = RangeError;

// https://tc39.es/proposal-change-array-by-copy/#sec-array.prototype.with
// https://tc39.es/proposal-change-array-by-copy/#sec-%typedarray%.prototype.with
module.exports = function (O, C, index, value) {
  var len = lengthOfArrayLike(O);
  var relativeIndex = toIntegerOrInfinity(index);
  var actualIndex = relativeIndex < 0 ? len + relativeIndex : relativeIndex;
  if (actualIndex >= len || actualIndex < 0) throw $RangeError('Incorrect index');
  var A = new C(len);
  var k = 0;
  for (; k < len; k++) A[k] = k === actualIndex ? value : O[k];
  return A;
};


/***/ }),

/***/ "d640":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


__webpack_require__("d9e2");
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.checkBounds = void 0;
function checkBounds(array, index) {
  if (index < 0 || index >= array.length) {
    throw new Error('Index out of bounds');
  }
}
exports.checkBounds = checkBounds;

/***/ }),

/***/ "d6c1":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


__webpack_require__("907a");
__webpack_require__("986a");
__webpack_require__("1d02");
__webpack_require__("3c5d");
__webpack_require__("1b3b");
__webpack_require__("3d71");
__webpack_require__("c6e3");
__webpack_require__("d9e2");
__webpack_require__("14d9");
__webpack_require__("13d5");
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.renderMerkleTree = exports.isValidMerkleTree = exports.processMultiProof = exports.getMultiProof = exports.processProof = exports.getProof = exports.makeMerkleTree = void 0;
const keccak_1 = __webpack_require__("a623");
const utils_1 = __webpack_require__("cc7b");
const bytes_1 = __webpack_require__("fb21");
const throw_error_1 = __webpack_require__("001f");
const hashPair = (a, b) => (0, keccak_1.keccak256)((0, utils_1.concatBytes)(...[a, b].sort(bytes_1.compareBytes)));
const leftChildIndex = i => 2 * i + 1;
const rightChildIndex = i => 2 * i + 2;
const parentIndex = i => i > 0 ? Math.floor((i - 1) / 2) : (0, throw_error_1.throwError)('Root has no parent');
const siblingIndex = i => i > 0 ? i - (-1) ** (i % 2) : (0, throw_error_1.throwError)('Root has no siblings');
const isTreeNode = (tree, i) => i >= 0 && i < tree.length;
const isInternalNode = (tree, i) => isTreeNode(tree, leftChildIndex(i));
const isLeafNode = (tree, i) => isTreeNode(tree, i) && !isInternalNode(tree, i);
const isValidMerkleNode = node => node instanceof Uint8Array && node.length === 32;
const checkTreeNode = (tree, i) => void (isTreeNode(tree, i) || (0, throw_error_1.throwError)('Index is not in tree'));
const checkInternalNode = (tree, i) => void (isInternalNode(tree, i) || (0, throw_error_1.throwError)('Index is not an internal tree node'));
const checkLeafNode = (tree, i) => void (isLeafNode(tree, i) || (0, throw_error_1.throwError)('Index is not a leaf'));
const checkValidMerkleNode = node => void (isValidMerkleNode(node) || (0, throw_error_1.throwError)('Merkle tree nodes must be Uint8Array of length 32'));
function makeMerkleTree(leaves) {
  leaves.forEach(checkValidMerkleNode);
  if (leaves.length === 0) {
    throw new Error('Expected non-zero number of leaves');
  }
  const tree = new Array(2 * leaves.length - 1);
  for (const [i, leaf] of leaves.entries()) {
    tree[tree.length - 1 - i] = leaf;
  }
  for (let i = tree.length - 1 - leaves.length; i >= 0; i--) {
    tree[i] = hashPair(tree[leftChildIndex(i)], tree[rightChildIndex(i)]);
  }
  return tree;
}
exports.makeMerkleTree = makeMerkleTree;
function getProof(tree, index) {
  checkLeafNode(tree, index);
  const proof = [];
  while (index > 0) {
    proof.push(tree[siblingIndex(index)]);
    index = parentIndex(index);
  }
  return proof;
}
exports.getProof = getProof;
function processProof(leaf, proof) {
  checkValidMerkleNode(leaf);
  proof.forEach(checkValidMerkleNode);
  return proof.reduce(hashPair, leaf);
}
exports.processProof = processProof;
function getMultiProof(tree, indices) {
  indices.forEach(i => checkLeafNode(tree, i));
  indices.sort((a, b) => b - a);
  if (indices.slice(1).some((i, p) => i === indices[p])) {
    throw new Error('Cannot prove duplicated index');
  }
  const stack = indices.concat(); // copy
  const proof = [];
  const proofFlags = [];
  while (stack.length > 0 && stack[0] > 0) {
    const j = stack.shift(); // take from the beginning
    const s = siblingIndex(j);
    const p = parentIndex(j);
    if (s === stack[0]) {
      proofFlags.push(true);
      stack.shift(); // consume from the stack
    } else {
      proofFlags.push(false);
      proof.push(tree[s]);
    }
    stack.push(p);
  }
  if (indices.length === 0) {
    proof.push(tree[0]);
  }
  return {
    leaves: indices.map(i => tree[i]),
    proof,
    proofFlags
  };
}
exports.getMultiProof = getMultiProof;
function processMultiProof(multiproof) {
  var _stack$pop;
  multiproof.leaves.forEach(checkValidMerkleNode);
  multiproof.proof.forEach(checkValidMerkleNode);
  if (multiproof.proof.length < multiproof.proofFlags.filter(b => !b).length) {
    throw new Error('Invalid multiproof format');
  }
  if (multiproof.leaves.length + multiproof.proof.length !== multiproof.proofFlags.length + 1) {
    throw new Error('Provided leaves and multiproof are not compatible');
  }
  const stack = multiproof.leaves.concat(); // copy
  const proof = multiproof.proof.concat(); // copy
  for (const flag of multiproof.proofFlags) {
    const a = stack.shift();
    const b = flag ? stack.shift() : proof.shift();
    stack.push(hashPair(a, b));
  }
  return (_stack$pop = stack.pop()) !== null && _stack$pop !== void 0 ? _stack$pop : proof.shift();
}
exports.processMultiProof = processMultiProof;
function isValidMerkleTree(tree) {
  for (const [i, node] of tree.entries()) {
    if (!isValidMerkleNode(node)) {
      return false;
    }
    const l = leftChildIndex(i);
    const r = rightChildIndex(i);
    if (r >= tree.length) {
      if (l < tree.length) {
        return false;
      }
    } else if (!(0, utils_1.equalsBytes)(node, hashPair(tree[l], tree[r]))) {
      return false;
    }
  }
  return tree.length > 0;
}
exports.isValidMerkleTree = isValidMerkleTree;
function renderMerkleTree(tree) {
  if (tree.length === 0) {
    throw new Error('Expected non-zero number of nodes');
  }
  const stack = [[0, []]];
  const lines = [];
  while (stack.length > 0) {
    const [i, path] = stack.pop();
    lines.push(path.slice(0, -1).map(p => ['   ', '│  '][p]).join('') + path.slice(-1).map(p => ['└─ ', '├─ '][p]).join('') + i + ') ' + (0, utils_1.bytesToHex)(tree[i]));
    if (rightChildIndex(i) < tree.length) {
      stack.push([rightChildIndex(i), path.concat(0)]);
      stack.push([leftChildIndex(i), path.concat(1)]);
    }
  }
  return lines.join('\n');
}
exports.renderMerkleTree = renderMerkleTree;

/***/ }),

/***/ "da5e":
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__.p + "client/img/invite-pic@2x.bb09ea2e.png";

/***/ }),

/***/ "de28":
/***/ (function(module, exports) {

module.exports = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACQAAAAkCAYAAADhAJiYAAAAAXNSR0IArs4c6QAAAWBJREFUWEft2L1KHkEYhuHLQrSx0ELE0oABCz0ELURS5CwsEjsRGzutVdBKQc/C0kr7BLTxBzRpxcJGUASjTNiFzQcfM7usiGGmm33/7n3eYZiZHv+O71jEOHo6bE2nNxhJDa4WDTA7qYE1/BoDneNzjUKpro2B/lTatIIfqRUjfk84Ss1VbdlLJWgOh6lJ2vT70ECfMIPBFhQJ3bguunBfzZeq0AK20dsCTDXFb3zBRfkxBSgoc/YGMCXDMabrAM1jvwh4xGULKvUXm29I9YwBPIRJikLLWC8gTjHVAtAkTip5wk4e9qsMVIqSFYots6xQViimQMye11BWKKZAzJ7X0P+pUOhrOcJ5tzzrvtt5qJvMGSi2ALNCH06hJWwW1L/wLfYHCfYx7Fb8hnHbeevolucrDhKKNHW5w1AZnPJK1oefmGhaMRK3irU6QMF3FFuYbemxIeS8wh42itvrX6ZXQqKqJYvuDhMAAAAASUVORK5CYII="

/***/ }),

/***/ "df7e":
/***/ (function(module, exports, __webpack_require__) {

var lengthOfArrayLike = __webpack_require__("07fa");

// https://tc39.es/proposal-change-array-by-copy/#sec-array.prototype.toReversed
// https://tc39.es/proposal-change-array-by-copy/#sec-%typedarray%.prototype.toReversed
module.exports = function (O, C) {
  var len = lengthOfArrayLike(O);
  var A = new C(len);
  var k = 0;
  for (; k < len; k++) A[k] = O[len - k - 1];
  return A;
};


/***/ }),

/***/ "dfb9":
/***/ (function(module, exports, __webpack_require__) {

var lengthOfArrayLike = __webpack_require__("07fa");

module.exports = function (Constructor, list) {
  var index = 0;
  var length = lengthOfArrayLike(list);
  var result = new Constructor(length);
  while (length > index) result[index] = list[index++];
  return result;
};


/***/ }),

/***/ "e00c":
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),

/***/ "e163":
/***/ (function(module, exports, __webpack_require__) {

var hasOwn = __webpack_require__("1a2d");
var isCallable = __webpack_require__("1626");
var toObject = __webpack_require__("7b0b");
var sharedKey = __webpack_require__("f772");
var CORRECT_PROTOTYPE_GETTER = __webpack_require__("e177");

var IE_PROTO = sharedKey('IE_PROTO');
var $Object = Object;
var ObjectPrototype = $Object.prototype;

// `Object.getPrototypeOf` method
// https://tc39.es/ecma262/#sec-object.getprototypeof
// eslint-disable-next-line es/no-object-getprototypeof -- safe
module.exports = CORRECT_PROTOTYPE_GETTER ? $Object.getPrototypeOf : function (O) {
  var object = toObject(O);
  if (hasOwn(object, IE_PROTO)) return object[IE_PROTO];
  var constructor = object.constructor;
  if (isCallable(constructor) && object instanceof constructor) {
    return constructor.prototype;
  } return object instanceof $Object ? ObjectPrototype : null;
};


/***/ }),

/***/ "e177":
/***/ (function(module, exports, __webpack_require__) {

var fails = __webpack_require__("d039");

module.exports = !fails(function () {
  function F() { /* empty */ }
  F.prototype.constructor = null;
  // eslint-disable-next-line es/no-object-getprototypeof -- required for testing
  return Object.getPrototypeOf(new F()) !== F.prototype;
});


/***/ }),

/***/ "e2a9":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SubscribeSelect_vue_vue_type_style_index_0_id_32fd27c8_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("473b");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SubscribeSelect_vue_vue_type_style_index_0_id_32fd27c8_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SubscribeSelect_vue_vue_type_style_index_0_id_32fd27c8_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "e8b5":
/***/ (function(module, exports, __webpack_require__) {

var classof = __webpack_require__("c6b6");

// `IsArray` abstract operation
// https://tc39.es/ecma262/#sec-isarray
// eslint-disable-next-line es/no-array-isarray -- safe
module.exports = Array.isArray || function isArray(argument) {
  return classof(argument) == 'Array';
};


/***/ }),

/***/ "ebb5":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var NATIVE_ARRAY_BUFFER = __webpack_require__("4b11");
var DESCRIPTORS = __webpack_require__("83ab");
var global = __webpack_require__("da84");
var isCallable = __webpack_require__("1626");
var isObject = __webpack_require__("861d");
var hasOwn = __webpack_require__("1a2d");
var classof = __webpack_require__("f5df");
var tryToString = __webpack_require__("0d51");
var createNonEnumerableProperty = __webpack_require__("9112");
var defineBuiltIn = __webpack_require__("cb2d");
var defineBuiltInAccessor = __webpack_require__("edd0");
var isPrototypeOf = __webpack_require__("3a9b");
var getPrototypeOf = __webpack_require__("e163");
var setPrototypeOf = __webpack_require__("d2bb");
var wellKnownSymbol = __webpack_require__("b622");
var uid = __webpack_require__("90e3");
var InternalStateModule = __webpack_require__("69f3");

var enforceInternalState = InternalStateModule.enforce;
var getInternalState = InternalStateModule.get;
var Int8Array = global.Int8Array;
var Int8ArrayPrototype = Int8Array && Int8Array.prototype;
var Uint8ClampedArray = global.Uint8ClampedArray;
var Uint8ClampedArrayPrototype = Uint8ClampedArray && Uint8ClampedArray.prototype;
var TypedArray = Int8Array && getPrototypeOf(Int8Array);
var TypedArrayPrototype = Int8ArrayPrototype && getPrototypeOf(Int8ArrayPrototype);
var ObjectPrototype = Object.prototype;
var TypeError = global.TypeError;

var TO_STRING_TAG = wellKnownSymbol('toStringTag');
var TYPED_ARRAY_TAG = uid('TYPED_ARRAY_TAG');
var TYPED_ARRAY_CONSTRUCTOR = 'TypedArrayConstructor';
// Fixing native typed arrays in Opera Presto crashes the browser, see #595
var NATIVE_ARRAY_BUFFER_VIEWS = NATIVE_ARRAY_BUFFER && !!setPrototypeOf && classof(global.opera) !== 'Opera';
var TYPED_ARRAY_TAG_REQUIRED = false;
var NAME, Constructor, Prototype;

var TypedArrayConstructorsList = {
  Int8Array: 1,
  Uint8Array: 1,
  Uint8ClampedArray: 1,
  Int16Array: 2,
  Uint16Array: 2,
  Int32Array: 4,
  Uint32Array: 4,
  Float32Array: 4,
  Float64Array: 8
};

var BigIntArrayConstructorsList = {
  BigInt64Array: 8,
  BigUint64Array: 8
};

var isView = function isView(it) {
  if (!isObject(it)) return false;
  var klass = classof(it);
  return klass === 'DataView'
    || hasOwn(TypedArrayConstructorsList, klass)
    || hasOwn(BigIntArrayConstructorsList, klass);
};

var getTypedArrayConstructor = function (it) {
  var proto = getPrototypeOf(it);
  if (!isObject(proto)) return;
  var state = getInternalState(proto);
  return (state && hasOwn(state, TYPED_ARRAY_CONSTRUCTOR)) ? state[TYPED_ARRAY_CONSTRUCTOR] : getTypedArrayConstructor(proto);
};

var isTypedArray = function (it) {
  if (!isObject(it)) return false;
  var klass = classof(it);
  return hasOwn(TypedArrayConstructorsList, klass)
    || hasOwn(BigIntArrayConstructorsList, klass);
};

var aTypedArray = function (it) {
  if (isTypedArray(it)) return it;
  throw TypeError('Target is not a typed array');
};

var aTypedArrayConstructor = function (C) {
  if (isCallable(C) && (!setPrototypeOf || isPrototypeOf(TypedArray, C))) return C;
  throw TypeError(tryToString(C) + ' is not a typed array constructor');
};

var exportTypedArrayMethod = function (KEY, property, forced, options) {
  if (!DESCRIPTORS) return;
  if (forced) for (var ARRAY in TypedArrayConstructorsList) {
    var TypedArrayConstructor = global[ARRAY];
    if (TypedArrayConstructor && hasOwn(TypedArrayConstructor.prototype, KEY)) try {
      delete TypedArrayConstructor.prototype[KEY];
    } catch (error) {
      // old WebKit bug - some methods are non-configurable
      try {
        TypedArrayConstructor.prototype[KEY] = property;
      } catch (error2) { /* empty */ }
    }
  }
  if (!TypedArrayPrototype[KEY] || forced) {
    defineBuiltIn(TypedArrayPrototype, KEY, forced ? property
      : NATIVE_ARRAY_BUFFER_VIEWS && Int8ArrayPrototype[KEY] || property, options);
  }
};

var exportTypedArrayStaticMethod = function (KEY, property, forced) {
  var ARRAY, TypedArrayConstructor;
  if (!DESCRIPTORS) return;
  if (setPrototypeOf) {
    if (forced) for (ARRAY in TypedArrayConstructorsList) {
      TypedArrayConstructor = global[ARRAY];
      if (TypedArrayConstructor && hasOwn(TypedArrayConstructor, KEY)) try {
        delete TypedArrayConstructor[KEY];
      } catch (error) { /* empty */ }
    }
    if (!TypedArray[KEY] || forced) {
      // V8 ~ Chrome 49-50 `%TypedArray%` methods are non-writable non-configurable
      try {
        return defineBuiltIn(TypedArray, KEY, forced ? property : NATIVE_ARRAY_BUFFER_VIEWS && TypedArray[KEY] || property);
      } catch (error) { /* empty */ }
    } else return;
  }
  for (ARRAY in TypedArrayConstructorsList) {
    TypedArrayConstructor = global[ARRAY];
    if (TypedArrayConstructor && (!TypedArrayConstructor[KEY] || forced)) {
      defineBuiltIn(TypedArrayConstructor, KEY, property);
    }
  }
};

for (NAME in TypedArrayConstructorsList) {
  Constructor = global[NAME];
  Prototype = Constructor && Constructor.prototype;
  if (Prototype) enforceInternalState(Prototype)[TYPED_ARRAY_CONSTRUCTOR] = Constructor;
  else NATIVE_ARRAY_BUFFER_VIEWS = false;
}

for (NAME in BigIntArrayConstructorsList) {
  Constructor = global[NAME];
  Prototype = Constructor && Constructor.prototype;
  if (Prototype) enforceInternalState(Prototype)[TYPED_ARRAY_CONSTRUCTOR] = Constructor;
}

// WebKit bug - typed arrays constructors prototype is Object.prototype
if (!NATIVE_ARRAY_BUFFER_VIEWS || !isCallable(TypedArray) || TypedArray === Function.prototype) {
  // eslint-disable-next-line no-shadow -- safe
  TypedArray = function TypedArray() {
    throw TypeError('Incorrect invocation');
  };
  if (NATIVE_ARRAY_BUFFER_VIEWS) for (NAME in TypedArrayConstructorsList) {
    if (global[NAME]) setPrototypeOf(global[NAME], TypedArray);
  }
}

if (!NATIVE_ARRAY_BUFFER_VIEWS || !TypedArrayPrototype || TypedArrayPrototype === ObjectPrototype) {
  TypedArrayPrototype = TypedArray.prototype;
  if (NATIVE_ARRAY_BUFFER_VIEWS) for (NAME in TypedArrayConstructorsList) {
    if (global[NAME]) setPrototypeOf(global[NAME].prototype, TypedArrayPrototype);
  }
}

// WebKit bug - one more object in Uint8ClampedArray prototype chain
if (NATIVE_ARRAY_BUFFER_VIEWS && getPrototypeOf(Uint8ClampedArrayPrototype) !== TypedArrayPrototype) {
  setPrototypeOf(Uint8ClampedArrayPrototype, TypedArrayPrototype);
}

if (DESCRIPTORS && !hasOwn(TypedArrayPrototype, TO_STRING_TAG)) {
  TYPED_ARRAY_TAG_REQUIRED = true;
  defineBuiltInAccessor(TypedArrayPrototype, TO_STRING_TAG, {
    configurable: true,
    get: function () {
      return isObject(this) ? this[TYPED_ARRAY_TAG] : undefined;
    }
  });
  for (NAME in TypedArrayConstructorsList) if (global[NAME]) {
    createNonEnumerableProperty(global[NAME], TYPED_ARRAY_TAG, NAME);
  }
}

module.exports = {
  NATIVE_ARRAY_BUFFER_VIEWS: NATIVE_ARRAY_BUFFER_VIEWS,
  TYPED_ARRAY_TAG: TYPED_ARRAY_TAG_REQUIRED && TYPED_ARRAY_TAG,
  aTypedArray: aTypedArray,
  aTypedArrayConstructor: aTypedArrayConstructor,
  exportTypedArrayMethod: exportTypedArrayMethod,
  exportTypedArrayStaticMethod: exportTypedArrayStaticMethod,
  getTypedArrayConstructor: getTypedArrayConstructor,
  isView: isView,
  isTypedArray: isTypedArray,
  TypedArray: TypedArray,
  TypedArrayPrototype: TypedArrayPrototype
};


/***/ }),

/***/ "edd0":
/***/ (function(module, exports, __webpack_require__) {

var makeBuiltIn = __webpack_require__("13d2");
var defineProperty = __webpack_require__("9bf2");

module.exports = function (target, name, descriptor) {
  if (descriptor.get) makeBuiltIn(descriptor.get, name, { getter: true });
  if (descriptor.set) makeBuiltIn(descriptor.set, name, { setter: true });
  return defineProperty.f(target, name, descriptor);
};


/***/ }),

/***/ "f3d7":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Reinvest_vue_vue_type_style_index_0_id_478f9844_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("6134");
/* harmony import */ var _node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Reinvest_vue_vue_type_style_index_0_id_478f9844_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_mini_css_extract_plugin_dist_loader_js_ref_9_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_9_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_9_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_9_oneOf_1_3_node_modules_cache_loader_dist_cjs_js_ref_1_0_node_modules_vue_loader_lib_index_js_vue_loader_options_Reinvest_vue_vue_type_style_index_0_id_478f9844_prod_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* unused harmony reexport * */


/***/ }),

/***/ "f495":
/***/ (function(module, exports, __webpack_require__) {

var toPrimitive = __webpack_require__("c04e");

var $TypeError = TypeError;

// `ToBigInt` abstract operation
// https://tc39.es/ecma262/#sec-tobigint
module.exports = function (argument) {
  var prim = toPrimitive(argument, 'number');
  if (typeof prim == 'number') throw $TypeError("Can't convert number to bigint");
  // eslint-disable-next-line es/no-bigint -- safe
  return BigInt(prim);
};


/***/ }),

/***/ "f8cd":
/***/ (function(module, exports, __webpack_require__) {

var toIntegerOrInfinity = __webpack_require__("5926");

var $RangeError = RangeError;

module.exports = function (it) {
  var result = toIntegerOrInfinity(it);
  if (result < 0) throw $RangeError("The argument can't be less than 0");
  return result;
};


/***/ }),

/***/ "fb21":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.hex = exports.compareBytes = void 0;
const utils_1 = __webpack_require__("cc7b");
function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}
exports.compareBytes = compareBytes;
function hex(b) {
  return '0x' + (0, utils_1.bytesToHex)(b);
}
exports.hex = hex;

/***/ }),

/***/ "fb6e":
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__.p + "client/img/recommend-dog@2x.22976c48.png";

/***/ })

}]);