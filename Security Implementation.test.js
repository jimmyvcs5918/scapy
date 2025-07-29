const { validateSecurity } = require('./webapp');

test('Security implementation should validate user input', () => {
	expect(validateSecurity('<script>alert("xss")</script>')).toBe(false);
});

test('Security implementation should allow safe input', () => {
	expect(validateSecurity('safeInput')).toBe(true);
});