import React from 'react';
import RegistrationForm from './components/RegistrationForm';

function App() {
    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100 py-12">
            <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
                <h1 className="text-2xl font-bold text-center mb-6">Register</h1>
                <RegistrationForm />
            </div>
        </div>
    );
}

export default App;
