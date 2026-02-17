export async function GET() {
  return Response.json({
    utc: new Date().toISOString(),
    unix: Date.now(),
    uptime: process.uptime(),
  });
}
