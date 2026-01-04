export function generateOtp(digits = 6) {
  const min = Math.pow(10, digits - 1);
  const num = Math.floor(min + Math.random() * (9 * min));
  return String(num);
}
