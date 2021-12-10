<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
//panggil model User
use App\Models\User;
//untuk autentikasi login 
use Illuminate\Support\Facades\Auth;
//untuk hash password 
use Illuminate\Support\Facades\Hash;
//untuk validasi
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request) 
    {
      //validasi
      $data = Validator::make($request->all(), [
        'name' => 'required',
        'email' => 'required|email|unique:users',
        'password' => 'required|min:8',
        'confirmPassword' => 'required|same:password'
      ]);
      
      //jika validasi gagal
      if($data->fails()) {
        return response()->json($data->errors(), 401);
      }
      
      //save 
      $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => Hash::make($request->password)
      ]);
      
      return response()->json([
        'message' => 'user berhasil dibuat',
        'user' => $user
      ], 200);
    }
    
    public function login(Request $request) 
    {
      //validasi
      $data = Validator::make($request->all(), [
        'email' => 'required|email',
        'password' => 'required|min:8'
      ]);
      
      //jika validasi gagal
      if($data->fails()) {
        return response()->json($data->errors(), 401);
      }
      
      //cari user sesuai email
      $user = User::where('email', $request->email)->first();
      
      
      //jika user tidak ditemukan
      if(!$user || !Hash::check($request->password, $user->password)) {
          return response()->json([
          'notMatch' => 'email atau password salah'
        ], 401);
      }
      
      return response()->json([
        'message' => 'Login sukses',
        'user' => $user,
        'token' => $user->createToken('authToken')->accessToken
      ], 200);
    }
    
    public function logout(Request $request)
    {
       if($request->user()) {
         $request->user()->tokens()->delete();
         
         return response()->json(['message' => 'logout sukses'], 200);
       }
    }
    
    public function getAuthenticatedUser() 
    {
      return response()->json([
        'userToken' => $request->user
      ], 200);
    }
}
