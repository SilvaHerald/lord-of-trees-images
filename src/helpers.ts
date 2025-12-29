export const isNumericString = (str: unknown) => {
	if (typeof str != 'string' || str.length === 0) return false;
	return Number.isFinite(+str);
};
