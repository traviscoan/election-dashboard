'use server';

import { z } from 'zod';
import { sql } from '@vercel/postgres';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { signIn } from '@/auth';
import { AuthError } from 'next-auth';
import bcrypt from 'bcrypt'
import { v4 as uuidv4 } from 'uuid';

const RegisterUser = z.object({
    name: z.string({
      invalid_type_error: 'Please enter your name.',
    }),
    email: z.string({
      invalid_type_error: 'Please enter an email address.',
    }),
    password: z.string({
      invalid_type_error: 'Please enter a password.',
    }),
    confirmPassword: z.string({
      invalid_type_error: 'Please confirm your password.',
    }),
  })
 
const FormSchema = z.object({
  id: z.string(),
  customerId: z.string(),
  amount: z.coerce.number(),
  status: z.enum(['pending', 'paid']),
  date: z.string(),
});
 
const CreateInvoice = FormSchema.omit({ id: true, date: true });

export async function createInvoice(formData: FormData) {
    const { customerId, amount, status } = CreateInvoice.parse({
        customerId: formData.get('customerId'),
        amount: formData.get('amount'),
        status: formData.get('status'),
    });

    const amountInCents = amount * 100;
    const date = new Date().toISOString().split('T')[0];
    await sql`
        INSERT INTO invoices (customer_id, amount, status, date)
        VALUES (${customerId}, ${amountInCents}, ${status}, ${date})
    `;

    revalidatePath('/dashboard/invoices');
    redirect('/dashboard/invoices');

}

export async function authenticate(
    prevState: string | undefined,
    formData: FormData,
  ) {
    try {
      await signIn('credentials', formData);
    } catch (error) {
      if (error instanceof AuthError) {
        switch (error.type) {
          case 'CredentialsSignin':
            return 'Invalid credentials.';
          default:
            return 'Something went wrong.';
        }
      }
      throw error;
    }
  }

  export async function register(
    prevState: string | null,
    formData: FormData,
  ) {
  
    const validatedFields = RegisterUser.safeParse({
      name: formData.get('name'),
      email: formData.get('email'),
      password: formData.get('password'),
      confirmPassword: formData.get('confirm-password'),
    })
  
    // If form validation fails, return errors early. Otherwise, continue.
    if (!validatedFields.success) {
      return "Missing Fields. Failed to Create Account."
    }
  
    const { name, email, password, confirmPassword } = validatedFields.data
  
    // Check if passwords match
    if (password !== confirmPassword) {
      return "Passwords don't match."
    }
  
    const hashedPassword = await bcrypt.hash(password, 10)
    const id = uuidv4()
  
    try {
      await sql`
        INSERT INTO users (id, name, email, password)
        VALUES (${id}, ${name}, ${email}, ${hashedPassword})
      `
    } catch (error) {
      return "Database Error: Failed to Create Account."
    }
  
    redirect('/login')
  }
