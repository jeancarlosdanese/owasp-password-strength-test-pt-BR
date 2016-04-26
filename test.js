var should = require('should');
var owasp  = require('./owasp-password-strength-test');

describe('senhas', function() {

  describe('testes necessários', function() {

    it('Comprimento mínimo deve ser executado', function() {
      var result = owasp.test('L0^eSex');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.requiredTestErrors.should.have.length(1);
      result.failedTests.should.containEql(0);
    });

    it('Comprimento máximo deve ser executado', function() {
      var password = '';
      for (var i = 0; i < 50; i++) {
        password += 'abc';
      }

      var result = owasp.test(password);
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.requiredTestErrors.should.have.length(1);
      result.failedTests.should.containEql(1);
    });

    it('repetição de caracteres por (3 vezes ou mais) devem ser proibidos', function() {
      var result = owasp.test('L0veSexxxSecre+God');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.requiredTestErrors.should.have.length(1);
      result.failedTests.should.containEql(2);
    });
  });

  describe('testes opcionais', function() {

    it('senhas válidas deve ser reconhecido como tal', function() {
      var result = owasp.test('L0veSexSecre+God');
      result.strong.should.be.true;
      result.errors.should.be.empty;
      result.requiredTestErrors.should.be.empty;
      result.optionalTestErrors.should.be.empty;
      result.failedTests.should.be.empty;
      result.passedTests.should.eql([0, 1, 2, 3, 4, 5, 6]);
    });

    it('pelo menos um caractere minúsculo deve ser exigido', function() {
      var result = owasp.test('L0VESEXSECRE+GOD');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(3);
    });

    it('pelo menos uma letra maiúscula deve ser exigida', function() {
      var result = owasp.test('l0vesexsecre+god');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(4);
    });

    it('pelo menos um número deve ser exigido', function() {
      var result = owasp.test('LoveSexSecre+God');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(5);
    });

    it('pelo menos um caractere especial deve ser exigido', function() {
      var result = owasp.test('L0veSexSecretGod');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(6);
    });

    it('os caracteres apropriados devem ser reconhecidos como especiais', function() {

      // see: https://www.owasp.org/index.php/Password_special_characters
      var specials = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'.split('');

      // test each special character
      specials.forEach(function(special) {
        var password = ['L0veSex', special, 'SecretGod'].join('');
        var result   = owasp.test(password);
        result.strong.should.be.true;
        result.errors.should.be.empty;
        result.requiredTestErrors.should.be.empty;
        result.optionalTestErrors.should.be.empty;
        result.failedTests.should.be.empty;
        result.passedTests.should.eql([0, 1, 2, 3, 4, 5, 6]);
      });
    });

  });
});

describe('frases de senha', function() {

  it('por padrão não deve ser sujeito a testes opcionais', function() {
    var result = owasp.test('Hack the planet! Hack the planet!');
    result.strong.should.be.true;
    result.errors.should.be.empty;
  });

  it('devem ser sujeitos a testes opcionais por configuração', function() {
    owasp.config({ allowPassphrases: false });
    owasp.test('Hack the planet! Hack the planet!').strong.should.be.false;
  });

});

describe('configurações', function() {

  it('deve ser ajustável', function() {
    owasp.config({
      allowPassphrases       : false,
      maxLength              : 5,
      minLength              : 5,
      minPhraseLength        : 5,
      minOptionalTestsToPass : 5,
    });
    owasp.configs.allowPassphrases.should.be.false;
    owasp.configs.maxLength.should.be.exactly(5);
    owasp.configs.minLength.should.be.exactly(5);
    owasp.configs.minPhraseLength.should.be.exactly(5);
    owasp.configs.minOptionalTestsToPass.should.be.exactly(5);
  });

  it('should reject invalid parameter keys', function() {
    owasp.config({ foo: 'bar' });
    owasp.configs.should.not.have.property('foo');
  });

});
