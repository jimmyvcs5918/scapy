test('API integration returns expected response', async () => {
	const response = await fetch('https://api.example.com/integration');
	const data = await response.json();
	expect(data).toHaveProperty('success', true);
});

test('API integration handles errors gracefully', async () => {
	const response = await fetch('https://api.example.com/integration/error');
	expect(response.status).toBe(500);
});