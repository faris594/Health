'use client'
import { useState } from "react";

export default function LoginForm() {
    const [formData, setFormData] = useState({
        email: "",
        password: "",
    });

    const [error, setError] = useState("");

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(""); // Clear previous errors

        try {
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(formData),
            });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem("token", data.token); // Save token for authentication
                alert("Login successful! ✅");
                window.location.href = "/dashboard"; // Redirect user
            } else {
                setError(data.message || "Invalid email or password ❌");
            }
        } catch (error) {
            console.error("Login error:", error);
            setError("Something went wrong!");
        }
    };

    return (
        <div className="flex justify-center items-center h-screen bg-gradient-to-br from-teal-600 to-teal-900">
            <div className="w-full max-w-4xl justify-center bg-gray-200 rounded-lg shadow-xl p-8 flex flex-col md:flex-row">
                <div className="w-full md:w-1/2 p-6">
                    <div className="flex items-center mb-6">
                        <img src="/images/logo.svg" alt="Health Care Logo" className="w-40 h-40 mr-4" />
                        <h2 className="text-3xl font-bold text-teal-500">Health Care</h2>
                    </div>

                    {error && <p className="text-red-500 text-sm mb-4">{error}</p>}

                    <form onSubmit={handleSubmit}>
                        <div className="mb-6">
                            <label className="block text-lg text-gray-700 mb-2" htmlFor="email">
                                Email
                            </label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                value={formData.email}
                                onChange={handleChange}
                                className="w-full p-4 border text-black border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-4 focus:ring-teal-500"
                                placeholder="Enter your email"
                                required
                            />
                        </div>
                        <div className="mb-6">
                            <label className="block text-lg text-gray-700 mb-2" htmlFor="password">
                                Password
                            </label>
                            <input
                                type="password"
                                id="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                                className="w-full p-4 border text-black rounded-lg shadow-sm border-gray-300 focus:outline-none focus:ring-4 focus:ring-teal-500"
                                placeholder="Enter your password"
                                required
                            />
                        </div>
                        <div className="flex justify-between items-center mb-6">
                            <a href="#" className="text-sm text-indigo-500 hover:text-indigo-700">Forgot Password?</a>
                        </div>
                        <button
                            type="submit"
                            className="w-full py-4 bg-teal-500 text-white text-lg rounded-lg shadow-lg hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500"
                        >
                            Login
                        </button>
                    </form>
                    <div className="mt-6 text-center">
                        <p className="text-sm text-gray-600">
                            Don't have an account?{' '}
                            <a href="/register" className="text-indigo-500 hover:text-indigo-700">Sign Up</a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
