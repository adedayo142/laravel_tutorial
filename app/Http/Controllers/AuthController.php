<?php

namespace App\Http\Controllers;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Http\RedirectResponse;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name'=> 'required|string|max:255',
            'email'=> 'required|string|email|unique:users,email',
            'password'=>'required|string|min:6|confirmed'
        ]);

        $user = User::create([
            'name'=> $validatedData['name'],
            'email'=> $validatedData['email'],
            'password'=> Hash::make($validatedData['password']),
            //'password'=> bcrypt($validatedData['password'])
        ]);
        //Generate a token for the newly registered user
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'access_token'=> $token,
            'token_type'=> 'Bearer',
            'user'=> $user,
            'message'=> "User registered successfully"], 201);
    }

    public function login(Request $request)
    {
        if(!Auth::attempt($request->only('email', 'password'))){
            return response()->json([
                'message'=> 'Invalid login details'
            ], 401);
        }
        $user = User::where('email', $request['email'])->firstOrFail();
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'access_token'=> $token,
            'token_type'=> 'Bearer',
            'message'=> "LoggedIn successfully"], 200);
       
        // $request->validate([
        //     'email'=> 'required|string|email',
        //     'password'=> 'required|string'
        // ]);

        // $user = User::where('email', $request->email)->first();
    }

    public function reset_password(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:6|confirmed',
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
        function ($user, $password) {
            $user->forceFill([
                'password' => Hash::make($password)
            ])->setRememberToken(Str::random(60));
 
            $user->save();
 
            event(new PasswordReset($user));
        }
    );
    return $status === Password::PASSWORD_RESET
    ? redirect()->route('login')->with('status', __($status))
    : back()->withErrors(['email' => [__($status)]]);

    }

    public function logout(Request $request): RedirectResponse
    {
        auth()->user()->tokens()->delete();
        return [
            'message'=> 'Logged Out'
        ];
    //     Auth::logout();
    //     $request->session()->invalidate();
 
    // $request->session()->regenerateToken();
    // return redirect('/');
    }

    public function me(Request $request)
    {
        return $request->user();
        if ($user) {
            return response()->json($user);
        } else {
            return response()->json(['message' => 'User not authenticated'], 401);
        }
    }
}
