"use server";

export async function searchLeakX(domain: string) {
  try {
    const response = await fetch(`https://leakix.net/domain/${domain}`, {
      headers: {
        "api-key": process.env.LEAKX_API_KEY as string,
        Accept: "application/json",
      },
    });

    
    

    if (!response.ok) {
      if (response.status === 404) {
        return { message: "No results found for this domain." };
      }
      throw new Error(`LeakX API error: ${response.statusText}`);
    }

    const data = await response.json();
    if (!data.Services && !data.Leaks) {
      return { message: "No services or leaks found for this domain." };
    }

    return data;
  } catch (error) {
    console.error("Failed to fetch LeakX data:", error);
    throw new Error("Failed to fetch LeakX data. Please try again later.");
  }
}

export async function searchShodan(ip: string) {
  try {
    const response = await fetch(
      `https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`
    );

    if (!response.ok) {
      throw new Error("Failed to fetch Shodan data");
    }

    return response.json();
  } catch (error) {
    throw new Error("Failed to fetch Shodan data");
  }
}
