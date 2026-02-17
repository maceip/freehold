export async function GET() {
  return Response.json({ message: "Hello from Freehold + Next.js!" });
}

export async function POST(request) {
  const body = await request.json();
  return Response.json({
    message: `Hello, ${body.name || "world"}!`,
    timestamp: new Date().toISOString(),
  });
}
